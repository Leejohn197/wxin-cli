/// Linux WeChat 进程内存密钥扫描器
///
/// 通过 /proc/<pid>/maps 枚举内存区域，
/// 通过 /proc/<pid>/mem 读取内存内容，
/// 搜索 x'<64hex><32hex>' 格式的 SQLCipher 密钥
use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use super::{collect_db_salts, KeyEntry};

const HEX_PATTERN_LEN: usize = 96;
const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 查找所有 WeChat 进程 PID（支持多开分身）
fn find_all_wechat_pids() -> Vec<u32> {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut pids = Vec::new();
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = format!("/proc/{}/comm", name_str);
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            let comm = comm.trim().to_lowercase();
            if comm == "wechat" || comm == "weixin" {
                if let Ok(pid) = name_str.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

/// 解析 /proc/<pid>/maps 文件，返回可读的内存区域 (start, end)
fn parse_maps(pid: u32) -> Result<Vec<(u64, u64)>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("读取 {} 失败", maps_path))?;

    let mut regions = Vec::new();
    for line in content.lines() {
        // 格式: start-end perms offset dev inode pathname
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1].trim_start();
        // 只选取 r 和 w 权限的区域
        if !perms.starts_with("rw") {
            continue;
        }
        let addr_parts: Vec<&str> = parts[0].splitn(2, '-').collect();
        if addr_parts.len() != 2 {
            continue;
        }
        if let (Ok(start), Ok(end)) = (
            u64::from_str_radix(addr_parts[0], 16),
            u64::from_str_radix(addr_parts[1], 16),
        ) {
            regions.push((start, end));
        }
    }
    Ok(regions)
}

pub fn scan_keys(db_dirs: &[PathBuf]) -> Result<Vec<KeyEntry>> {
    let pids = find_all_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 WeChat 进程，请确认 WeChat 正在运行");
    }
    eprintln!("找到 {} 个 WeChat 进程: {:?}", pids.len(), pids);

    // 收集所有 db_dir 的 salt 映射
    let all_db_salts: Vec<(&PathBuf, Vec<(String, String)>)> = db_dirs
        .iter()
        .map(|dir| {
            let salts = collect_db_salts(dir);
            eprintln!("目录 {} 找到 {} 个加密数据库", dir.display(), salts.len());
            (dir, salts)
        })
        .collect();

    for pid in &pids {
        eprintln!("尝试 PID {} ...", pid);

        let regions = match parse_maps(*pid) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  PID {} 解析 maps 失败: {}，跳过", pid, e);
                continue;
            }
        };
        eprintln!("  PID {} 找到 {} 个可读写内存区域", pid, regions.len());

        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = match std::fs::File::open(&mem_path) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("  PID {} 打开 {} 失败，跳过", pid, mem_path);
                continue;
            }
        };

        let mut raw_keys: Vec<(String, String)> = Vec::new();
        for (start, end) in &regions {
            scan_region(&mut mem_file, *start, *end, &mut raw_keys);
        }
        eprintln!("  PID {} 找到 {} 个候选密钥", pid, raw_keys.len());

        if raw_keys.is_empty() {
            continue;
        }

        // 尝试匹配每个 db_dir
        for (db_dir, db_salts) in &all_db_salts {
            if db_salts.is_empty() {
                continue;
            }
            let mut entries = Vec::new();
            for (key_hex, salt_hex) in &raw_keys {
                for (db_salt, db_name) in db_salts {
                    if salt_hex == db_salt {
                        entries.push(KeyEntry {
                            db_name: db_name.clone(),
                            enc_key: key_hex.clone(),
                            salt: salt_hex.clone(),
                        });
                        break;
                    }
                }
            }
            if !entries.is_empty() {
                eprintln!(
                    "  PID {} × {} 匹配到 {} 个密钥 ✓",
                    pid,
                    db_dir.display(),
                    entries.len()
                );
                return Ok(entries);
            }
        }
        eprintln!("  PID {} 的密钥与所有数据目录均不匹配", pid);
    }

    bail!(
        "扫描了 {} 个进程、{} 个数据目录，均未匹配到密钥",
        pids.len(),
        db_dirs.len()
    )
}

fn scan_region(
    mem: &mut std::fs::File,
    start: u64,
    end: u64,
    results: &mut Vec<(String, String)>,
) {
    let total_len = (end - start) as usize;
    let overlap = HEX_PATTERN_LEN + 3;
    let mut offset = 0usize;

    loop {
        if offset >= total_len {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, total_len - offset);
        let addr = start + offset as u64;

        if mem.seek(SeekFrom::Start(addr)).is_err() {
            break;
        }
        let mut buf = vec![0u8; chunk_size];
        match mem.read(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                search_pattern(&buf, results);
            }
            _ => {}
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

#[inline]
fn is_hex_char(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    let total = HEX_PATTERN_LEN + 3;
    if buf.len() < total {
        return;
    }
    let mut i = 0;
    while i + total <= buf.len() {
        if buf[i] != b'x' || buf[i + 1] != b'\'' {
            i += 1;
            continue;
        }
        let hex_start = i + 2;
        let all_hex = buf[hex_start..hex_start + HEX_PATTERN_LEN]
            .iter()
            .all(|&c| is_hex_char(c));
        if !all_hex {
            i += 1;
            continue;
        }
        if buf[hex_start + HEX_PATTERN_LEN] != b'\'' {
            i += 1;
            continue;
        }
        let key_hex = String::from_utf8_lossy(&buf[hex_start..hex_start + 64])
            .to_lowercase();
        let salt_hex = String::from_utf8_lossy(&buf[hex_start + 64..hex_start + 96])
            .to_lowercase();
        let is_dup = results.iter().any(|(k, s)| k == &key_hex && s == &salt_hex);
        if !is_dup {
            results.push((key_hex, salt_hex));
        }
        i += total;
    }
}
