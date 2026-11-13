# CMS `signedAttrs` 混淆离线回归材料

面向后端验签团队的离线回归套件：用 `asn1crypto` 在 ASN.1 层构造各种
`SignedAttributes` 混淆结构，用一个最小验证适配器表达“验签前必须拒绝什么”，
并对每个反例提供只改一处的合法对照，确保普通签名与合法副署不会被一起误拒。

## 为什么不能先转字典

`SignedAttributes` / `UnsignedAttributes` 是 `SET OF Attribute`。把它转成
`dict[attrType] = attribute` 会用键去重，**静默抹掉重复的 attrType 出现**，
而重复出现正是要检测的混淆。本套件始终：

- 在原始 `CMSAttributes`（`SetOf`）上按索引遍历；
- 用 `verifier.index_attributes()` 维护有序列表 + `oid -> [出现次数]` 多重映射；
- 同时检查三视图：原始集合、惰性访问（`attrs[i]['values'][j]`）后的取值、DER 输出；
- 对 DER 做 `load -> dump` 往返，断言重复项与多值 SET 在编码后仍然存在。

注意 `asn1crypto` 的 `CMSAttributeType.native` 返回的是映射短名
（如 `content_type`），不是点分 OID；`verifier._normalize_oid()` 统一两种表示。

## 三阶段验证（解析成功 ≠ 签名有效）

`verifier.verify_content_info()` 把判定显式拆成三层，结构层拒绝先于任何密码学操作：

1. **结构检查**：重复 attrType、单值属性带多个值、缺失必备属性、content-type 与
   外层 `eContentType` 不一致、副署放错位置等。命中即 `rejected_structure`，
   `signature_status = not_attempted`。
2. **本地摘要绑定**：用标准库 `hashlib` 重新计算摘要。
   - 普通 SignerInfo：`message-digest` 必须等于 `digest(eContent)`。
   - 副署：RFC 5652 11.4 禁止副署带 `message-digest`，因此从 PKCS#1 签名里恢复
     DigestInfo 的摘要，与 `digest(父 SignerInfo.signature OCTETS)` 比对。
3. **密码学验签**：可插拔后端。本套件用 `builder.py` 里仅用于测试的纯标准库
   RSASSA-PKCS1-v1_5 实现，并已用 `openssl pkeyutl` 交叉验证。生产环境必须替换为
   受审计的加密库；解析成功只代表 ASN.1 合法，不代表签名有效。

签名输入按 RFC 5652 5.4 处理：`signedAttrs` 在 SignerInfo 内是隐式 `[0] SET`
（标签 `0xA0`），但签名覆盖的是通用 `SET` 标签（`0x31`）的 DER，仅首字节不同。
`builder.signed_attrs_der_for_signing()` 负责这个标签转换。

## 用例矩阵

合法对照（必须接受）：

- `valid_baseline`：普通签名，content-type + message-digest + signing-time。
- `valid_countersignature`：合法副署，位于 unsignedAttrs，无 content-type/
  message-digest，签名直接覆盖父签名字节。
- `dup_countersignature_attr`：两个 countersignature unsigned 属性。RFC 5652 11.4
  明确允许多个副署属性，这是 11.3“禁止重复属性”的例外，用于防止过度拒绝。

反例（每个相对其 `legal_control` 只改一处，改完重新签名）：

| 用例 | 预期拒绝码 | 依据 |
| --- | --- | --- |
| `dup_content_type` | `duplicate_attr_type` | RFC 5652 11.3 |
| `dup_message_digest` | `duplicate_attr_type` | RFC 5652 11.3 |
| `multi_value_content_type` | `multi_value_attribute` | RFC 5652 11.2 |
| `multi_value_message_digest` | `multi_value_attribute` | RFC 5652 11.2 |
| `missing_content_type` | `missing_required_attribute` | RFC 5652 5.3 |
| `missing_message_digest` | `missing_required_attribute` | RFC 5652 5.3 |
| `content_type_mismatch` | `content_type_econtent_type_mismatch` | RFC 5652 5.3 |
| `digest_mismatch` | `message_digest_payload_mismatch` | RFC 5652 5.4 |
| `countersignature_in_signed_attrs` | `countersignature_must_be_unsigned` | RFC 5652 11.4 |
| `countersigner_has_content_type` | `countersigner_forbidden_signed_attr` | RFC 5652 11.4 |
| `countersigner_has_message_digest` | `countersigner_forbidden_signed_attr` | RFC 5652 11.4 |
| `countersigner_binds_econtent` | `message_digest_payload_mismatch`（绑定层） | RFC 5652 11.4 |

反例在变异后都会重新签名，因此对 `signedAttrs` 的签名本身仍然可验证
（`ParseIsNotValidationTests` 专门断言这一点），证明拒绝来自结构/绑定规则，
而不是因为签名坏了。`countersigner_binds_econtent` 的结构是合法的，属于绑定层
拒绝（`rejected_signature`），其余结构反例在验签前就拒绝。

## 目录与运行

- `builder.py`：CMS 组装、SET 标签转换、测试专用 RSA/PKCS#1 原语与 DigestInfo 恢复。
- `verifier.py`：最小验证适配器与全部拒绝码。
- `corpus.py`：用例定义；运行后在 `generated/` 写 DER 与 `manifest.json`。
- `run_report.py`：不依赖 pytest 的命令行报告。
- `test_signedattrs_regression.py`：16 个 unittest/pytest 用例。
- `fixtures/`：离线 RSA 密钥与自签证书，`make_fixtures.sh` 可重新生成。

```sh
# 重新生成 DER 语料
python regression_cms_signedattrs/corpus.py
# 文本报告（后端联调用）
python regression_cms_signedattrs/run_report.py
# 测试，两种 runner 均可
python -m pytest regression_cms_signedattrs -q
python -m unittest regression_cms_signedattrs.test_signedattrs_regression -v
```

## 边界

- 仅覆盖 RSA + SHA-256 + attached id-data 与 countersignature 路径，用于表达规则；
  生产适配器需扩展算法白名单、 detached content、证书链与撤销校验。
- `builder.py` 的 RSA 代码是测试夹具，不是通用加密实现，禁止用于生产验签。
- 私钥随夹具保存仅为本地可复现，不代表任何真实身份；上线材料应只保留 DER/证书。
