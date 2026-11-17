# windows-service-permission-auditor

Python Windows 服务权限审计库：判断低权限用户能否替换服务二进制、修改启动参数或重配服务。

## 功能

输入 SCM 导出（`sc qc` 文本）、服务账户、可执行路径、文件/父目录 ACL、服务控制权限和依赖关系，输出每个服务的能力判定与证据：

- `replace_binary` — 可替换服务二进制
- `modify_parameters` — 可修改启动参数 / 脚本内容
- `reconfigure_service` — 可通过 `SERVICE_CHANGE_CONFIG` 等重配服务

证据类型（`EvidenceKind`）：

| 证据 | 含义 |
| --- | --- |
| `writable_file` | 攻击者对服务二进制持有写权限 |
| `writable_parent_dir` | 父目录可写，可删除并重建二进制 |
| `owner_control` | 攻击者是对象所有者或持有 WRITE_DAC/WRITE_OWNER |
| `weak_service_acl` | 服务对象 DACL 允许低权限用户改配置 |
| `script_interpreter_path` | 服务以脚本（.ps1/.bat/.py 等）经解释器启动 |
| `unquoted_path` | 未加引号且含空格的路径，可植入 `Program.exe` 等 |
| `dependency_chain` | 依赖的服务可被劫持，风险沿依赖链传播 |
| `dependency_cycle` | 检测到依赖环（不会死循环） |
| `path_not_found` | 快照中缺少该路径的 ACL，结论为 UNKNOWN |

严重度：高权限账户（LocalSystem/LocalService/NetworkService）被劫持为 `CRITICAL`，普通用户服务为 `HIGH`，缺少 ACL 数据为 `UNKNOWN`。

## 用法

```python
from winsvc_audit import AuditEngine, ObjectACL, AceEntry, Rights, parse_scm_export

services = parse_scm_export(open("sc_qc.txt", encoding="utf-8").read())
engine = AuditEngine(
    attacker="CORP\\lowpriv",
    attacker_groups={"Everyone", "BUILTIN\\Users"},
    file_acls={"C:\\svc\\svc.exe": ObjectACL(owner="BUILTIN\\Administrators", entries=[...])},
    dir_acls={"C:\\svc": ObjectACL(owner="CORP\\lowpriv", entries=[...])},
)
reports = engine.audit(services)
for name, report in reports.items():
    print(name, report.severity.value, [c.value for c in report.capabilities])
```

## 测试

```
python -m unittest
```

覆盖：SYSTEM 服务、普通用户服务、空服务目录、依赖环、相同 ACL 不同所有者、弱服务 ACL、脚本解释器路径、未加引号路径、deny 优先、SCM 导出解析。

## 与真实 Windows ACL 求值的差异

本库是**离线模型**，不是 `AccessCheck` 的重实现，结论用于巡检分流而非最终裁决：

- **输入为已解析的有效 ACL**：假设调用方已完成继承展开（container/object inherit、inherit-only 标志），库内不处理继承与 ACE 顺序。
- **简化的主体匹配**：仅按用户名/组名字符串匹配，不展开嵌套组成员、SID 历史、well-known SID 或登录会话产生的动态组（如 INTERACTIVE）。
- **deny 优先的集合法则**：有效权限 = allow 并集 − deny 并集；真实 Windows 还考虑 ACE 顺序（非规范顺序 DACL）与 masked generic 映射的细节。
- **所有者即控制权**：所有者隐含 `WRITE_DAC`，与真实行为一致；但不模拟 `SeTakeOwnershipPrivilege`、管理员组接管所有权等提权路径。
- **不模拟令牌状态**：完整性级别（UAC）、受限令牌、特权启用/禁用状态（如 `SeRestorePrivilege` 隐含 WRITE_DAC）均未建模。
- **路径处理是静态的**：不解析符号链接、junction、环境变量展开、`PATH` 中解释器的实际落点；未加引号路径的候选列表是理论枚举，未逐一核对真实文件系统。
- **依赖链传播是保守近似**：依赖服务被劫持即视为风险沿链传播，未建模依赖服务是否实际启动、失败动作（failure actions）或运行账户差异。
- **脚本解释器**：仅按扩展名提示风险，不检查脚本签名策略（如 PowerShell Execution Policy、AppLocker/WDAC）。

生产使用时，建议用 `Get-Acl`/`sc.exe sdshow` 导出已解析的 DACL 与所有者作为输入，并把 `UNKNOWN` 结果交给人工复核。
