# wx-cli 安全审查报告

**项目版本:** 0.1.10  
**审查日期:** 2026-05-13  
**审查范围:** 全部源代码（31个 .rs 文件）  
**审查方法:** 静态代码分析 + 模式匹配

---

## 📋 目录

- [一、执行摘要](#一执行摘要)
- [二、信息泄露风险分析](#二信息泄露风险分析)
- [三、后门分析](#三后门分析)
- [四、零日漏洞风险分析](#四零日漏洞风险分析)
- [五、风险汇总](#五风险汇总)
- [六、安全亮点](#六安全亮点)
- [七、修复建议](#七修复建议)
- [八、结论](#八结论)

---

## 一、执行摘要

### 整体安全评估: ✅ 良好

wx-cli 是一个设计良好的本地工具，**未发现任何后门代码**。主要安全风险集中在信息泄露和理论上的漏洞利用，都需要本地访问权限且利用难度较高。

### 关键发现

| 类别 | 状态 | 说明 |
|------|------|------|
| 后门 | ✅ 未发现 | 无隐藏网络通信、数据收集或命令执行 |
| 信息泄露 | ⚠️ 中等风险 | 日志和缓存文件可能泄露敏感信息 |
| 零日漏洞 | ⚠️ 低-中风险 | 存在理论可利用漏洞，需本地权限 |

---

## 二、信息泄露风险分析

### 2.1 网络通信泄露 ✅ 安全

**检查项:** 外部网络请求

**结果:** 无

- 没有引入 `reqwest`、`hyper`、`curl` 等网络库
- 没有 `TcpStream`、`UdpSocket` 等网络连接
- 没有 `https?://` 硬编码的外部端点（测试用例中的 URL 是微信 CDN 的占位符）

**结论:** 代码本身不会向外部发送任何数据

---

### 2.2 日志信息泄露 ⚠️ 中等风险

**位置:** 多处 `eprintln!` 输出

```rust
// daemon/mod.rs:39
eprintln!("[daemon] DB_DIR: {}", cfg.db_dir.display());

// daemon/mod.rs:46  
eprintln!("[daemon] 密钥数量: {}", all_keys.len());

// daemon/cache.rs:178
eprintln!("[cache] 解密 {} ({}ms)", rel_key, elapsed_ms);

// scanner/macos.rs:105
eprintln!("找到 {} 个 WeChat 进程: {:?}", pids.len(), pids);
```

**泄露内容:**
- 数据库目录路径（可推断用户微信账号结构）
- 密钥数量（可推断数据库规模）
- 解密的数据库文件名（MD5 哈希，可关联到联系人）
- 进程 PID（可用于进一步攻击）

**风险评估:** 日志写入 `~/.wx-cli/daemon.log`，权限由 umask 决定（0o077），但如果没有正确设置，可能被其他用户读取。

**建议:**
```rust
// 只记录相对路径，不记录完整路径
eprintln!("[cache] 解密 {} ({}ms)", 
    rel_key.split('/').last().unwrap_or("?"), elapsed_ms);
```

---

### 2.3 缓存文件泄露 ⚠️ 中等风险

**位置:** src/daemon/cache.rs

```rust
// 第 90 行 - 解密后的数据库文件
let mut output = std::fs::File::create(out_path)?;

// 第 115 行 - mtime 持久化文件
let _ = tokio::fs::write(&mtime_file, json).await;
```

**泄露内容:**
- `~/.wx-cli/cache/*.db` - 解密后的完整数据库（明文 SQLite）
- `~/.wx-cli/cache/_mtimes.json` - 数据库文件路径和修改时间

**风险评估:** 
- 目录权限 0700，但文件本身没有显式设置权限（可能是默认 0644）
- 缓存在 daemon 生命周期内持续存在，退出时不清理
- 攻击者如果获得用户权限，可以直接读取解密后的数据库

**建议:**
```rust
// 创建文件时显式设置权限
use std::os::unix::fs::OpenOptionsExt;
let output = OpenOptions::new()
    .create(true).write(true)
    .mode(0o600)
    .open(out_path)?;

// daemon 退出时清理缓存
fn cleanup_and_exit() {
    let _ = std::fs::remove_dir_all(config::cache_dir());
    // ...
}
```

---

### 2.4 状态文件泄露 ⚠️ 低风险

**位置:** src/cli/new_messages.rs

```rust
fn state_file() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".wx-cli")
        .join("last_check.json")
}
```

**泄露内容:**
- `~/.wx-cli/last_check.json` - 包含所有会话的 username 和时间戳

---

### 2.5 PID 文件泄露 ⚠️ 低风险

**位置:** src/daemon/mod.rs

```rust
tokio::fs::write(config::pid_path(), pid.to_string()).await?;
```

**泄露内容:**
- `~/.wx-cli/daemon.pid` - daemon 进程 ID

---

## 三、后门分析

### 3.1 隐藏网络通信 ✅ 未发现

```
检查项: 隐藏的 HTTP/DNS 请求
结果: 无
```

- 没有 DNS 解析代码
- 没有 HTTP 客户端
- 没有 WebSocket 连接
- 没有 SMTP 邮件发送

**结论:** 不存在数据外传后门

---

### 3.2 隐藏命令执行 ✅ 安全

**位置:** 多处 `Command::new`

```rust
// scanner/macos.rs:82 - 查找进程
Command::new("pgrep").args(["-x", "WeChat"])

// transport.rs:121 - 启动 daemon
Command::new(&exe).env("WX_DAEMON_MODE", "1")

// daemon_cmd.rs:55 - 停止 daemon (Windows)
Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"])

// daemon_cmd.rs:77 - 查看日志
Command::new("tail").args([&format!("-{}", lines), "-f", &log_path.to_string_lossy()])
```

**分析:**
- 所有命令都是明确的功能需求
- 没有动态构造的命令字符串
- 没有 shell 执行 (`sh -c`, `cmd /c`)

**结论:** 不存在命令注入后门

---

### 3.3 隐藏文件操作 ✅ 安全

```
检查项: 写入到意外位置的文件操作
结果: 所有写入都在 ~/.wx-cli/ 目录内
```

**写入位置清单:**
- `~/.wx-cli/config.json` - 配置文件
- `~/.wx-cli/all_keys.json` - 加密密钥
- `~/.wx-cli/daemon.sock` - Unix socket
- `~/.wx-cli/daemon.pid` - PID 文件
- `~/.wx-cli/daemon.log` - 日志文件
- `~/.wx-cli/cache/*.db` - 解密缓存
- `~/.wx-cli/cache/_mtimes.json` - mtime 记录
- `~/.wx-cli/last_check.json` - 消息检查状态

**结论:** 没有写入到系统目录、临时目录或其他意外位置

---

### 3.4 隐藏数据收集 ✅ 未发现

```
检查项: 收集系统信息、用户行为数据
结果: 无
```

- 没有收集 MAC 地址、主机名、用户名
- 没有记录用户命令历史
- 没有上传使用统计

**结论:** 不存在数据收集后门

---

### 3.5 供应链攻击检查 ⚠️ 建议验证

**位置:** Cargo.toml 依赖

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "=1.0.140"
rusqlite = { version = "0.31", features = ["bundled"] }
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
hmac = "0.12"
sha2 = "0.10"
pbkdf2 = "0.12"
zstd = "0.13"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
dirs = "5"
md5 = "0.7"
regex = "1"
roxmltree = "0.20"
```

**分析:**
- 所有依赖都是知名 crate，有良好的维护记录
- `serde_json = "=1.0.140"` 使用精确版本锁定，防止意外更新
- 加密库来自 RustCrypto 项目，经过审计

**建议:**
```bash
cargo install cargo-audit
cargo audit
```

---

## 四、零日漏洞风险分析

### 4.1 SQL 注入 ⚠️ 中等风险

**位置:** src/daemon/query.rs

```rust
// 第 441 行
&format!("SELECT MAX(create_time) FROM [{}]", tname)

// 第 493 行
format!("SELECT ... FROM [{}] {} ORDER BY ...", table, where_clause)

// 第 566 行
format!("SELECT ... FROM [{}] {} ORDER BY ...", table, where_clause)
```

**风险点:**
- 表名通过 `format!` 直接拼接
- 虽然有正则验证 (`^Msg_[0-9a-f]{32}$`)，但不够健壮
- 如果正则被绕过或代码变更，将产生 SQL 注入

**缓解措施:**
- 表名来自 MD5 哈希，格式固定
- 使用 `[{}]` 方括号转义（SQLite 特性）

**建议:**
```rust
// 使用白名单验证表名
fn is_valid_msg_table(name: &str) -> bool {
    name.starts_with("Msg_") && name.len() == 36 
        && name[4..].chars().all(|c| c.is_ascii_hexdigit())
}
```

---

### 4.2 内存安全问题 (unsafe) ⚠️ 低-中风险

**位置:** src/scanner/macos.rs

```rust
// 第 254-255 行
let buf: &[u8] = unsafe {
    std::slice::from_raw_parts(data as *const u8, dc as usize)
};

// 第 262 行
unsafe {
    mach_vm_deallocate(mach_task_self(), data as u64, dc as u64);
}
```

**风险点:**
- `mach_vm_read` 返回的指针可能无效（如果目标进程内存被释放）
- `dc as usize` 在 32 位系统上可能截断
- 没有验证 `data` 指针是否对齐

**缓解措施:**
- 代码在 `kr == KERN_SUCCESS` 后才使用指针
- 使用 `mach_vm_deallocate` 正确释放内存

**风险等级:** 低-中（需要目标进程配合）

---

### 4.3 整数溢出 ⚠️ 低风险

**位置:** 多处类型转换

```rust
// scanner/linux.rs:165
let total_len = (end - start) as usize;  // u64 -> usize，在 32 位系统上溢出

// crypto/mod.rs:85
let file_size = input.metadata()?.len() as usize;  // u64 -> usize

// daemon/query.rs:689
let base = (t as u64 & 0xFFFFFFFF) as i64;  // 可能溢出
```

**风险点:**
- 在 32 位系统上，`u64 -> usize` 转换会截断
- 大文件（>4GB）可能导致 `usize` 溢出
- 时间戳转换可能产生意外值

**缓解措施:**
- 代码主要运行在 64 位系统上
- 使用了 `saturating_add` 等安全算术

**风险等级:** 低（64 位系统上基本安全）

---

### 4.4 竞态条件 (TOCTOU) ⚠️ 低风险

**位置:** src/cli/transport.rs

```rust
// 第 57-62 行
if is_alive() {
    return Ok(());
}
// ... 时间窗口 ...
start_daemon()?;
```

**风险点:**
- 检查 daemon 是否存活和启动 daemon 之间存在时间窗口
- 攻击者可以在这个窗口内创建恶意 socket 文件
- 类似的 TOCTOU 问题存在于文件存在性检查

**缓解措施:**
- socket 文件权限 0600
- daemon 使用 `UnixListener::bind` 原子创建

**风险等级:** 低（需要本地访问权限）

---

### 4.5 路径遍历 ⚠️ 低风险

**位置:** src/daemon/cache.rs

```rust
// 第 81 行
let db_path = self.db_dir.join(rel_key.replace('\\', std::path::MAIN_SEPARATOR_STR)
    .replace('/', std::path::MAIN_SEPARATOR_STR));
```

**风险点:**
- `rel_key` 来自 `all_keys.json`，如果被篡改可能包含 `../`
- `join` 函数会解析 `..`，可能导致路径遍历

**缓解措施:**
- `rel_key` 格式为 `message/message_0.db`，由程序生成
- 密钥文件权限 0600

**风险等级:** 低（需要篡改密钥文件）

---

### 4.6 资源耗尽 (DoS) ⚠️ 低风险

**位置:** src/daemon/server.rs

```rust
// 第 44-54 行
loop {
    let (stream, _) = listener.accept().await?;
    tokio::spawn(async move {
        // 处理连接...
    });
}
```

**风险点:**
- 没有连接数限制
- 每个连接都 spawn 一个新任务
- 恶意客户端可以创建大量连接耗尽资源

**缓解措施:**
- socket 权限 0600，只有同用户可以连接
- 连接处理是短暂的（单请求-响应模式）

**风险等级:** 低（需要本地用户权限）

**建议:**
```rust
// 添加最大连接数限制
let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
loop {
    let (stream, _) = listener.accept().await?;
    let permit = semaphore.clone().acquire_owned().await?;
    tokio::spawn(async move {
        let _permit = permit; // 自动释放
        // 处理连接...
    });
}
```

---

### 4.7 格式化字符串漏洞 ✅ 未发现

```
检查项: 动态格式化字符串
结果: 所有格式化字符串都是字面量
```

- 所有 `format!`、`eprintln!` 使用字面量格式字符串
- 没有用户输入直接作为格式化字符串

**结论:** 不存在格式化字符串漏洞

---

### 4.8 未初始化内存 ✅ 未发现

```
检查项: 读取未初始化内存
结果: 无
```

- 所有缓冲区都使用 `vec![0u8; size]` 初始化
- 没有使用 `MaybeUninit` 或 `std::mem::uninitialized`

**结论:** 不存在未初始化内存问题

---

## 五、风险汇总

| 类别 | 风险项 | 严重程度 | 可利用性 | 建议 |
|------|--------|----------|----------|------|
| 信息泄露 | 日志泄露敏感路径 | 中 | 低 | 减少详细路径输出 |
| 信息泄露 | 缓存文件未清理 | 中 | 中 | 退出时清理缓存 |
| 信息泄露 | 缓存文件权限 | 低-中 | 中 | 显式设置 0600 |
| 后门 | 隐藏网络通信 | 无 | N/A | ✅ 安全 |
| 后门 | 隐藏命令执行 | 无 | N/A | ✅ 安全 |
| 后门 | 供应链攻击 | 低 | 低 | 运行 cargo audit |
| 零日漏洞 | 内存安全 (unsafe) | 低-中 | 低 | 添加更多边界检查 |
| 零日漏洞 | 整数溢出 | 低 | 低 | 使用 checked 算术 |
| 零日漏洞 | 竞态条件 | 低 | 低 | 使用原子操作 |
| 零日漏洞 | SQL 注入 | 中 | 低 | 使用参数化表名 |
| 零日漏洞 | 路径遍历 | 低 | 低 | 验证路径格式 |
| 零日漏洞 | 资源耗尽 | 低 | 低 | 添加连接限制 |

---

## 六、安全亮点

1. **无网络通信**: 代码完全本地运行，不存在数据外传风险
2. **权限降权**: init.rs 在扫描后正确降权到调用用户
3. **umask 设置**: 使用 0o077 确保新文件默认私有
4. **socket 权限**: Unix socket 设置 0600 权限
5. **安全算术**: 使用 `saturating_add` 等防止溢出
6. **无动态命令**: 所有命令都是字面量，无注入风险
7. **依赖版本锁定**: 关键依赖使用精确版本

---

## 七、修复建议

### 优先级 P0（立即修复）

#### 1. SQL 注入防护

```rust
// src/daemon/query.rs

/// 验证表名是否为合法的 Msg_<md5> 格式
fn is_valid_msg_table(name: &str) -> bool {
    if !name.starts_with("Msg_") || name.len() != 36 {
        return false;
    }
    name[4..].chars().all(|c| c.is_ascii_hexdigit())
}

// 在使用表名前验证
if !is_valid_msg_table(&tname) {
    anyhow::bail!("非法表名: {}", tname);
}
```

#### 2. 缓存文件权限

```rust
// src/crypto/mod.rs

use std::os::unix::fs::OpenOptionsExt;

pub fn full_decrypt(db_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)  // 显式设置权限
        .open(out_path)?;
    
    // ... 其余代码
}
```

---

### 优先级 P1（尽快修复）

#### 3. 日志脱敏

```rust
// src/daemon/cache.rs

/// 脱敏路径，只保留最后一级目录名
fn sanitize_path_for_log(path: &str) -> String {
    path.split('/')
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/")
}

// 使用
eprintln!("[cache] 解密 {} ({}ms)", 
    sanitize_path_for_log(rel_key), elapsed_ms);
```

#### 4. 缓存清理

```rust
// src/daemon/mod.rs

fn cleanup_and_exit() {
    // 清理缓存目录
    let cache_dir = config::cache_dir();
    if cache_dir.exists() {
        let _ = std::fs::remove_dir_all(&cache_dir);
    }
    
    // 清理 socket 和 PID 文件
    let _ = std::fs::remove_file(config::sock_path());
    let _ = std::fs::remove_file(config::pid_path());
    
    std::process::exit(0);
}
```

#### 5. 连接限制

```rust
// src/daemon/server.rs

use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn serve(
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Arc<Names>>>,
) -> Result<()> {
    let max_connections = 100;
    let semaphore = Arc::new(Semaphore::new(max_connections));
    
    #[cfg(unix)]
    serve_unix(db, names, semaphore).await?;
    
    Ok(())
}

#[cfg(unix)]
async fn serve_unix(
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Arc<Names>>>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    // ... 其余代码 ...
    
    loop {
        let (stream, _) = listener.accept().await?;
        let db2 = Arc::clone(&db);
        let names2 = Arc::clone(&names);
        let sem = Arc::clone(&semaphore);
        
        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if let Err(e) = handle_connection_unix(stream, db2, names2).await {
                eprintln!("[server] 连接处理错误: {}", e);
            }
        });
    }
}
```

---

### 优先级 P2（计划修复）

#### 6. 安装 cargo-audit

```bash
cargo install cargo-audit
cargo audit
```

#### 7. 添加完整性验证

```rust
// src/daemon/cache.rs

use rusqlite::Connection;

/// 验证解密后的数据库完整性
fn verify_db_integrity(path: &Path) -> Result<bool> {
    let conn = Connection::open(path)?;
    let result: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    Ok(result == "ok")
}

// 在解密后验证
if !verify_db_integrity(&out_path)? {
    eprintln!("[cache] 警告: {} 完整性检查失败", rel_key);
    // 可选择删除损坏的缓存
    let _ = std::fs::remove_file(&out_path);
}
```

#### 8. 添加 unsafe 代码审计注释

```rust
// src/scanner/macos.rs

/// # Safety
/// 
/// 此函数使用 unsafe 代码读取目标进程内存。
/// 
/// 安全保证:
/// 1. `task` 是通过 `task_for_pid` 获取的有效 task port
/// 2. `mach_vm_read` 返回的指针在 `KERN_SUCCESS` 时有效
/// 3. 使用 `mach_vm_deallocate` 正确释放内核内存
/// 4. 缓冲区长度由内核返回的 `dc` 参数确定
/// 
/// # Panics
/// 
/// 如果 `data` 指针无效或 `dc` 超出缓冲区范围，可能导致 UB。
/// 当前实现依赖 Mach API 的正确行为。
unsafe fn read_process_memory(task: mach_port_t, addr: mach_vm_address_t, size: mach_vm_size_t) -> Result<Vec<u8>> {
    // ... 实现
}
```

---

## 八、结论

### 整体评估

wx-cli 是一个安全意识良好的项目，主要特点：

1. **完全本地运行** - 没有任何网络通信，数据不会泄露到外部
2. **正确的权限管理** - 使用 umask、文件权限、权限降权等机制
3. **无后门代码** - 经过全面审查，未发现任何隐藏的恶意功能
4. **安全的依赖选择** - 使用知名、经过审计的 crate

### 主要改进方向

1. **强化 SQL 注入防护** - 使用参数化表名或白名单验证
2. **改进缓存文件安全** - 显式设置权限、退出时清理
3. **添加日志脱敏** - 减少敏感路径信息的输出
4. **安装依赖审计工具** - 定期检查已知漏洞

### 风险等级

- **后门风险:** ✅ 无
- **信息泄露风险:** ⚠️ 中等（需要本地访问权限）
- **零日漏洞风险:** ⚠️ 低-中（需要本地访问权限且利用难度较高）

---

## 附录 A: 审查工具和方法

- **静态代码分析:** 手动审查所有 .rs 文件
- **模式匹配:** 搜索网络请求、命令执行、文件操作等模式
- **依赖分析:** 检查 Cargo.toml 中的依赖版本
- **unsafe 审计:** 审查所有 unsafe 代码块

## 附录 B: 审查文件清单

```
src/
├── main.rs
├── config.rs
├── ipc.rs
├── crypto/
│   ├── mod.rs
│   └── wal.rs
├── scanner/
│   ├── mod.rs
│   ├── macos.rs
│   ├── linux.rs
│   └── windows.rs
├── daemon/
│   ├── mod.rs
│   ├── server.rs
│   ├── query.rs
│   └── cache.rs
└── cli/
    ├── mod.rs
    ├── init.rs
    ├── transport.rs
    ├── daemon_cmd.rs
    ├── export.rs
    ├── new_messages.rs
    └── ... (其他命令)
```

---

**审查完成时间:** 2026-05-13  
**审查人:** Hermes Agent  
**报告版本:** 1.0
