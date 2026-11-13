# CSR extensionRequest 提取审查（asn1crypto 1.5.1）

面向使用 `asn1crypto` 的证书签发后端，回答三个问题：

1. `extensionRequest` 属性在一个 CSR 里出现多次时会怎样？
2. 同一份申请内出现重复扩展（相同 `extnID`）时会怎样？
3. Microsoft  enrollment 属性与标准 `extensionRequest` 同时出现时会怎样？

结论先行：**asn1crypto 是忠实的 DER 编解码器，不做任何属性唯一性或扩展去重校验，也没有 CSR 级便利访问器。歧义不会报错，而是原样保留到字节层；是否合并、取哪一份、是否签发，全部取决于调用方代码。** 本目录提供可运行的冲突样本、严格提取契约、反模式演示和策略层骨架。

## 目录内容

| 文件 | 作用 |
| --- | --- |
| `build_samples.py` | 用 asn1crypto 构造 6 个 CSR，再经 OpenSSL CLI 做 RSA-SHA256 自签名，输出 DER/PEM 与 `manifest.json` |
| `strict_extraction.py` | 推荐的提取契约：保留出处（provenance），遇到歧义抛 `AmbiguousRequest` |
| `naive_antipatterns.py` | 三种真实常见的“合并成一份合法配置”写法（后写覆盖、只取第一个、native 字典化） |
| `analyze_samples.py` | 逐样本输出结构、重编码行为、严格提取结果、反模式实际胜出的申请 |
| `reencoding_demo.py` | 演示 `SetOf` 重排序与字节缓存行为 |
| `certificate_accessor_demo.py` | 演示 `x509.Certificate` 便利访问器同样是后写覆盖 |
| `issuing_policy_skeleton.py` | 解析层与签发策略层之间的边界骨架（不是 CA） |
| `test_extraction_contract.py` | 19 项 pytest 契约/策略测试 |
| `generated/` | 已生成的 6 个 CSR（DER+PEM）、公钥对应私钥、清单、分析输出 |

运行方式（仓库根目录，需要系统 `openssl`，无需第三方 Python 加密库）：

```bash
python3 samples/csr_extension_audit/build_samples.py
python3 samples/csr_extension_audit/analyze_samples.py
python3 samples/csr_extension_audit/reencoding_demo.py
python3 samples/csr_extension_audit/certificate_accessor_demo.py
python3 -m pytest samples/csr_extension_audit -v
```

## 一、源码依据：从 CertificationRequestInfo 到重编码的完整路径

### 1.1 类型结构（`asn1crypto/csr.py`）

- `CertificationRequestInfo`（csr.py:119）的 `attributes` 字段类型是 `CRIAttributes(SetOf)`，带 `{'implicit': 0, 'optional': True}`。缺省时该字段是 `core.VOID` 哨兵，不是空列表。
- `CRIAttributes` 继承 `SetOf`（csr.py:115），`_child_spec = CRIAttribute`。`SetOf` 底层是 **list，不去重**（core.py:4166 的 `SequenceOf`，`children` 为普通列表）。
- `CRIAttribute`（csr.py:98）是 `Sequence`，字段为 `type: CSRAttributeType` 与 `values: Any`，通过 `_oid_pair = ('type', 'values')` 和 `_oid_specs` 做 OID 分发；`extension_request` 对应的规格是 `SetOfExtensions`（csr.py:108）。
- `SetOfExtensions`（csr.py:69）仍是 `SetOf`，其每个子元素是一个完整的 `x509.Extensions`（SEQUENCE OF Extension）。即 **RFC 2986 的 `SET OF Extension` 在建模上允许包含多个 `Extensions` 值**，库不限制只能有一个。
- `x509.Extensions(SequenceOf)`（x509.py:2143）同样是 list；`x509.Extension`（x509.py:2105）只定义字段，没有任何 `extnID` 唯一性检查。RFC 5280 §4.1.2.9 要求证书内扩展 OID 唯一，但该约束没有在类型层实现。

### 1.2 OID 懒解析路径

- `Sequence._determine_spec`（core.py:3777-3781）读取 `_oid_nums` 指向的 OID 字段，在 `_oid_specs` 命中时把 `Any` 字段替换为目标规格。对已 `load()` 的 CSR，访问 `attr['values']` 得到的已经是 `SetOfExtensions` 实例（而不是 `Any` 包装）；新构造路径上可能仍是 `Any`，需要用 `isinstance(values_field, core.Any)` 兼容（本目录的 `_extension_values` 辅助函数即处理此差异）。
- 未知 OID 不会失败：`ExtensionId(ObjectIdentifier)` 的 `native` 在 `_map` 未命中时返回点分 OID 字符串本身；`Extension._oid_specs` 未命中时 `extn_value` 保留为 `ParsableOctetString` 原始字节，`.parsed` 按通用规则解析。因此“未知 critical 扩展”可以完整穿过解析器。

### 1.3 存储与重编码

- `SequenceOf._parse_children`（core.py:4495-4529）把每个子元素 append 进列表，重复项全部保留。
- `SequenceOf.native`（core.py:4543-4564）返回 Python `list`；`Sequence.native`（core.py:4057-4088）返回 `OrderedDict`，字段名固定（`type`/`values`、`extn_id`/`critical`/`extn_value`），重复的列表元素不会在这一层丢失——丢失只会发生在调用方自己再建 `{oid: ...}` 字典时。
- `SetOf._set_contents`（core.py:4817-4836）重编码时对所有子元素的 DER 字节做 `sorted()`：**只排序、不去重**。因此：
  - 未修改对象的 `.dump()` 走字节缓存，对歧义输入也是字节级保真（`reencoding_demo.py` 验证 plain/force dump 均与原件一致），第二个解析器看到完全相同的歧义；
  - 一旦发生 append/修改触发重新生成内容，属性顺序按 DER 字典序变化，不能再用位置标识属性，只能用解析对象上的 OID/索引。
- `Any.dump`（core.py:1007-1022）委托给内部 parsed 对象，`ParsableOctetString`（core.py:2729 起）保留原始 `extnValue` 字节，整条链路没有任何净化步骤。

### 1.4 便利访问器的后写覆盖

`asn1crypto.csr` **没有任何便利访问器**，只有数据类型。便利访问器存在于 `x509.Certificate`：`_set_extensions`（x509.py:2202-2218）对扩展列表循环执行 `setattr(self, '_<name>_value', ...)`，重名扩展被最后一个静默覆盖，`critical_extensions` 集合则会累加所有 critical 标记。`certificate_accessor_demo.py` 实测：四个扩展（两个 BC、两个 SAN）编码后，`basic_constraints_value` 返回最后一个 `CA:TRUE, pathlen:2`，SAN 只剩 `evil.example`，全程无异常。把同样的列表搬进 TBS 并不会让库替你拒绝歧义。

## 二、样本矩阵与实测行为

所有样本均通过 `openssl req -verify` 自签名校验。**自签名只证明持有对应私钥（POP），不证明任何扩展主张合法，也不消除结构歧义。**

| 样本 | 结构 | 严格契约 | 反模式 `flatten_last_wins` 的实际结果 |
| --- | --- | --- | --- |
| `01_baseline_wellformed` | 1 属性 / 1 值 / OID 唯一（对照） | 接受，2 扩展带出处 | BC `CA:FALSE`；SAN `baseline.example` |
| `02_dup_attribute` | 两个并列 `extensionRequest` 属性 | **拒绝**：属性数必须为 1 | 第二个属性胜出：BC `CA:TRUE,pathlen:0`、critical SAN `internal/corp.example` |
| `03_multi_value` | 一个属性的 SET 内有两个 `Extensions` 值 | **拒绝**：SET 内值必须为 1 | 第二值的 `CA:TRUE` 覆盖第一值；EKU 被并入 |
| `04_dup_extnid` | 一个 Extensions 内 BC、SAN 各出现两次 | **拒绝**：`extnID` 必须唯一 | 后者胜出：`CA:TRUE,pathlen:2`、critical SAN `evil.example`，第一份受限主张消失 |
| `05_ms_and_standard` | 三个 Microsoft 属性 + 一个标准 `extensionRequest`（含 `CA:TRUE`、受限外 SAN、`microsoft_enroll_certtype`） | 结构接受（属性数=1），扩展与元数据分列；策略层拒绝 `CA:TRUE` | 原样保留 `CA:TRUE` 主张 |
| `06_unknown_critical` | 未知 OID `1.3.6.1.4.1.99999.7.1` 标记 critical | 结构接受，`extn_name=None`、`parsed=None`、原始字节与 critical 位保留 | 未知扩展以原始 OID 为键进入字典，语义被绕过 |

完整实测输出见 `generated/analyze_output.txt`（由 `analyze_samples.py` 生成）。

### 关于“Microsoft 形式与标准形式同时出现”

需要区分两类东西，它们在 asn1crypto 里是不同层面：

- **CSR 属性层**（`CRIAttributeType._map`，csr.py:40-51）：`microsoft_enrollment_csp_provider`（1.3.6.1.4.1.311.13.2.2）、`microsoft_os_version`（1.3.6.1.4.1.311.13.2.3）、`microsoft_request_client_info`（1.3.6.1.4.1.311.21.20）是携带 CSP/OS/客户端信息的**独立属性，不是扩展**，永远不应被提升为证书扩展。仓库自带夹具 `tests/fixtures/test-windows-host.csr` 就是这三个属性与一个标准 `extension_request` 并存的真实例子（见 tests/test_csr.py:143 的断言）。
- **扩展层**：Microsoft 自己的扩展 OID（如 `microsoft_enroll_certtype` 1.3.6.1.4.1.311.20.2，x509.py:2101）只能出现在标准 `extensionRequest` 里面。并不存在第二个“Microsoft 版 extensionRequest 属性 OID”；所谓冲突是 Microsoft 元数据属性与标准扩展申请同处一个 `attributes` SET，加上扩展申请内部本身可以携带冲突内容。

样本 05 复现该形态：严格提取器把三个 MS 属性放进 `other_attributes`（仅作申请者元数据记录），把标准申请里的三个扩展放进 `extensions` 并完整保留 `CA:TRUE` 与 critical SAN 主张；随后由策略骨架拒绝越权主张。

## 三、哪些只是申请者声明，哪些必须由签发策略决定

解析层（asn1crypto + 严格提取器）只能证明“申请者在 CSR 里编码了这些字节”。下列内容**全部是申请者声明**，不产生任何授权：

- `basicConstraints` 的 `CA`、`pathLenConstraint` 及其 critical 位；
- `subjectAltName` 的所有名字、名字类型与 critical 位（critical 位本身也是申请值）；
- `keyUsage`/`extKeyUsage`、`certificatePolicies` 等所有扩展内容；
- 任何未知 OID 的存在与 critical 标记；
- Microsoft 属性里的机器名、用户名、进程名、CSP 名称、OS 版本。

必须由签发策略决定、解析器无权决定的事项：

- 是否接受该 CSR 的整体结构（歧义即拒绝，而不是合并）；
- 是否允许 `CA=true`、多大的 `pathLen`、哪些 EKU/KU；
- SAN 与认证主体/租户的归属校验、允许的后缀或名字类型、最终 critical 位；
- 未知 critical 扩展：无法解释就必须拒绝（RFC 5280 §4.2 要求识别 critical 扩展，否则该证书不可用于该用途）；未知非 critical 扩展默认不复制进证书；
- 元数据属性仅用于审计/风控，不进入扩展序列。

`issuing_policy_skeleton.py` 把这条边界落成代码：结构歧义 → `PolicyDenial`；`CA:true` → 拒绝；SAN 后缀校验失败 → 拒绝；SAN 的最终 critical 位由策略强制为 `False`；未知 critical → 拒绝。实测六个样本中只有基线被允许进入签发流程，其余五种全部拒绝。

## 四、推荐的提取契约

维护者接入时应满足以下契约（参考实现即 `strict_extraction.py`）：

1. **输入归一化**：接受 `CertificationRequest` 或 DER/PEM 字节；`attributes` 为 `core.VOID` 时返回零扩展结果，而不是抛 `AttributeError`。
2. **属性计数**：遍历 `CRIAttributes`，点分 OID 等于 `1.2.840.113549.1.9.14` 的属性必须恰好 1 个；0 个走“无扩展申请”路径，多于 1 个直接拒绝（不要按位置取第一个，也不要拼接）。
3. **SET 基数**：该属性 `values`（解析为 `SetOfExtensions`）必须恰好包含 1 个 `Extensions`；多于 1 个直接拒绝。
4. **扩展 OID 唯一**：遍历唯一的 `Extensions`，记录每个 `extnID` 的索引；重复即拒绝，并在错误信息中给出 OID 与重复位置，便于审计。
5. **保留出处与原始字节**：对每个扩展返回 `index / extn_id(点分) / extn_name(未知为 None) / critical / raw_extn_value(bytes) / parsed(未知 OID 为 None)`。策略判断一律基于这份结构化结果，不要在解析层做 `{oid: ext}` 字典化。
6. **非扩展属性分流**：其他 OID（含三个 Microsoft 属性）进入单独的 `other_attributes` 列表，仅供审计，禁止提升为扩展。
7. **不信任重编码后的位置**：任何 `dump()`/重新 `load()` 之后，用 OID 与解析期索引标识对象；`SetOf` 重编码会按 DER 字典序排序（core.py:4836）。
8. **策略与解析分离**：提取器只做“拒绝歧义或如实描述”，不包含 allowlist、不签发、不改写 critical 位；所有授权决策在独立策略层显式表达。

最小接入示意：

```python
from strict_extraction import AmbiguousRequest, extract_csr_extensions

def intake(csr_bytes):
    try:
        claims = extract_csr_extensions(csr_bytes)  # 歧义在此被拒绝
    except AmbiguousRequest as exc:
        return reject('ambiguous extensionRequest: %s' % exc)
    return policy.review(claims)   # CA=true / SAN / unknown-critical 在此裁决
```

## 五、给维护者的反模式清单

- `{extn_id: extension}` 字典合并（`naive_antipatterns.flatten_last_wins`）：重复 OID 后写覆盖，样本 02/03/04 中攻击者放置的第二份 `CA:TRUE` 直接生效。
- 只读取第一个 `extensionRequest`（`first_attribute_only`）：丢弃后续属性，审计日志与实际签发内容不一致，且依赖 `SetOf` 的偶然顺序。
- 依赖 `.native` 后手工 squash（`native_dict_squash`）：`Sequence.native` 本身不丢数据，但再建 dict 时同样丢失重复项，并把未知 OID 弱化为无类型键。
- 假设“进了 `x509.Certificate` 访问器就安全”：`_set_extensions` 同样后写覆盖（见 1.4）。
- 把 Microsoft 属性当作扩展来源、或用自签名校验替代结构与策略校验。

## 六、范围说明

- 本审查只覆盖 CSR 扩展**申请的提取与歧义处理**，不主张修改 asn1crypto：它的定位是编解码器，把唯一性/策略约束塞进类型层会把解析器变成半个 CA，违背其职责。拒绝逻辑应位于调用方。
- 签名通过 OpenSSL CLI 完成以避免引入额外 Python 依赖；生产环境应使用与后端一致的签名/验签栈，并在验签（含 POP、签名算法强度）通过后再执行本契约。
- RFC 依据：RFC 2986（CSR/属性语法）、RFC 5280 §4.1.2.9（扩展 OID 唯一）与 §4.2（critical 扩展处理）、RFC 2985（属性 OID）、MS-WCCE（Microsoft enrollment 属性）。
