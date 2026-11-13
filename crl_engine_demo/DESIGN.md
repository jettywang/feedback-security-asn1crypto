# 间接 CRL / Delta CRL 组合算法设计（基于 asn1crypto 解析对象）

纯内存原型，无网络、无线上 CA。签名验证以可注入的 `verifier(CertificateList) -> bool`
表示；生产环境替换为「按 AKI 找 CRL 签发者证书 → 验签 → 该证书链到信任锚」即可，
组合逻辑与签名算法无关。

## 1. 两层模型：解析结果 ≠ 吊销结论

| 层 | 对象 | 含义 | 能否驱动决策 |
|---|---|---|---|
| 解析层 | `ParsedCRL` / `ParsedEntry`，`trust=PARSED` | asn1crypto 从 DER 解出的全部内容 | 否 |
| 信任层 | `ScopeState.facts: dict[EntryKey, RevocationFact]` | 仅来自验签+时效+顺序检查通过的 CRL | 是 |

`CRLEngine.ingest()` 顺序固定为 `parse() -> establish_trust() -> merge`。
任一步抛 `TrustBoundaryError`，作用域状态不发生任何修改；查询侧对应输出
`UNKNOWN`（无输入/无法判断）而不是隐式 "good"。

## 2. 身份键：为什么不能只按序列号合并

`EntryKey = (certificateIssuer 的 RDNSequence DER, userCertificate 序列号)`。

- 间接 CRL 里两个 CA 可以复用同一序列号（RFC 5280 §5.2.5 示例），它们是两张证书。
- 签发者用 Name 的 DER 归一化比较（RFC 5280 §7.1），等价 DN 的不同字符串编码不产生新键。
- 序列号单独作为键会把 CA Alpha/CA Beta 的同号条目互相覆盖，是安全缺陷。

## 3. certificateIssuer 沿撤销条目的继承规则

RFC 5280 §5.2.5，按 `revokedCertificates` 的物理顺序维护一个「运行中签发者」：

1. 初始值 = CRL 的 `issuer`（CRL 签发者自己签发的证书不需要该扩展）。
2. 条目带 `certificateIssuer`（OID 2.5.29.29，`GeneralNames` 中的
   `directoryName`）→ 用它更新运行中签发者，并作用于**当前条目**。
3. 条目不带该扩展 → 继承当前运行中签发者（`inherited_from_previous=True`）。
4. 该状态持续到下一个 `certificateIssuer` 再次改写它——不是每条重置。
5. 一致性检查：出现该扩展或 `removeFromCRL` 但 IDP 的 `indirectCRL` 未置位 →
   记 `parse_warnings`（asn1crypto 的 `RevokedCertificate.issuer_name` 只返回
   条目自带扩展、无扩展时为 `None`，继承必须由本引擎补齐）。

Delta 内的继承独立重放：delta 条目流自己的运行中签发者从 CRL issuer 起步，
与 base 的条目位置无关；键计算规则完全一致，所以 base 与 delta 的同键匹配天然正确。

## 4. 作用域（scope）：base 与 delta 能合并的前提

`CRLScope` 抽取并逐字段比较，任一不同即拒绝合并（delta 不得静默开新流）：

- CRL issuer Name DER
- IDP 整体 DER + 结构化字段：分发点名（`fullName`）、
  `onlyContainsUserCerts / onlyContainsCACerts / onlyContainsAttributeCerts`、
  `onlySomeReasons`（存 BitString content 字节，绕开 IMPLICIT [3] 标签）、
  `indirectCRL`
- `onlySomeReasons` 还参与条目级判定：reason 不在位集合内的条目不具权威性，
  该作用域内视为未列入（`reason_in_scope()`）。

## 5. Delta 链接与编号顺序

- delta 必须带 `deltaCRLIndicator`，其值 `baseCRLNumber`；base/delta 都必须有
  `cRLNumber`（单调递增）。
- 严格模式（RFC 5280 字面）：`baseCRLNumber == 当前 base 编号`。
- 放松模式（常见实现）：允许当前 base 更新，要求
  `baseCRLNumber <= 当前 base 编号 < delta 编号`；其余检查不放松。
- 始终强制：delta 编号 > 当前 base 编号；delta 按编号严格递增到达，
  重复编号/乱序编号一律拒绝并要求从 base 重建。
- 新 base 是该流的完整快照：替换全部 facts，再按编号重放仍可链接的 delta。

## 6. removeFromCRL 的状态语义（RFC 5280 §5.2.4）

| base 中现状 | delta 条目 | 演算结果 |
|---|---|---|
| `certificateHold` | `removeFromCRL` | `REVOKED(hold)` → `REMOVED`（本 CRL 视图内不再吊销） |
| 任意确定性 reason（keyCompromise 等） | `removeFromCRL` | 拒绝，保持原 `REVOKED`；确定性吊销不可被 delta 撤销 |
| `certificateHold` | 新的确定性 reason | 覆盖为新 reason，仍为 `REVOKED`（hold 转正式吊销） |
| 键不存在 | `removeFromCRL` | no-op，查询仍为 `NOT_LISTED` |
| 键不存在/已存在 | 普通 reason | 新增/覆盖为 `REVOKED`，记录来源 CRL 编号与 kind |

`REMOVED` 只表示「该作用域 CRL 不再列它」，不是证书有效：证书链、有效期、
其他作用域 CRL/OCSP 的结论仍独立成立。

## 7. 必须停止判断（fail-closed）的输入条件

- delta 先于任何 base 到达 → 无法解释 removeFromCRL，拒绝。
- `baseCRLNumber` 大于本地最新 base（严格模式下不相等同理）→ 停止并拉取指定 base。
- delta/ base 编号乱序或重复 → 拒绝，从最新 base 重建。
- delta 与 base 的 issuer 或 IDP 语义（分发点/证书类型/reason 集合）不相容 → 拒绝合并。
- 验签失败、CRL 过了 `nextUpdate`、`thisUpdate` 在未来 → 不进入信任层。
- 零 CRL 查询 → `UNKNOWN`。任何情况下都不把「数据缺失」当作「未吊销」。

## 8. 文件与运行

- `model.py`：两层数据模型、`EntryKey`、`CRLScope`、状态枚举。
- `engine.py`：解析与继承、scope 抽取、信任门禁、base/delta 合并、逐条 trace。
- `builder.py`：asn1crypto 内存 DER CRL 构造（占位签名 OID，无密钥运算）。
- `demo.py`：A 继承/同号冲突、B removeFromCRL 全分支、C 错误 base/乱序、
  D 范围不相容/reason 集合、E 信任边界与时效，五个场景逐条演算。
- `test_crl_engine.py`：同内容的 pytest 回归。

```
.venv/bin/python -m crl_engine_demo.demo
.venv/bin/python -m pytest crl_engine_demo/test_crl_engine.py -q
```
