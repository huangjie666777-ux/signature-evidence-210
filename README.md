# Archive TSA — RFC 3161 时间戳后端

为档案摘要签发可离线核验的 RFC 3161 时间回执（TimeStampResp）。FastAPI 0.115.12 + Python 3.10，签名由 OpenSSL 3.0.2 `ts -reply` 子进程完成。

## 运行

```bash
.venv/bin/python -m uvicorn signature_evidence210.main:app --host 127.0.0.1 --port 8016
```

首次启动在空的数据目录生成演示根 CA 与 RSA TSA 证书（EKU 仅含 critical 的 timeStamping）。重启复用现有材料；私钥缺失、与证书不匹配或 EKU 不合规时拒绝启动。私钥只存在于数据目录（0600），任何 HTTP 接口均不暴露。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `TSA_DATA_DIR` | `data` | 证书、密钥、SQLite、序列号文件所在目录 |
| `TSA_POLICY_OID` | `1.3.6.1.4.1.99999.210.1` | 默认策略 OID（请求省略时使用） |
| `TSA_ACCEPTED_POLICIES` | 同默认策略 | 额外接受的策略 OID，逗号分隔 |
| `TSA_MAX_REQUEST_BYTES` | `65536` | 请求体上限，超出返回 413 |
| `TSA_MAX_CONCURRENCY` | `4` | 并发签发上限，饱和返回 503 |
| `TSA_SIGN_TIMEOUT` | `10` | OpenSSL 签名子进程时限（秒） |

## 接口

- `POST /tsa`：请求 `application/timestamp-query`，响应 `application/timestamp-reply`（DER）。仅接受版本 1、SHA-256/SHA-384；校验摘要长度、完整 DER（无尾随字节）；未知策略与任何扩展返回对应 `PKIStatusInfo`（rejection + failInfo），无令牌。
- `GET /tsa/cert`：TSA 签名证书（PEM）。
- `GET /tsa/chain`：TSA 证书 + 根 CA（PEM）。
- `GET /tsa/receipt/{serial}`：按序列号取回原始回执 DER。

## 行为要点

- TSTInfo 保留请求摘要、策略与可选 nonce（无 nonce 亦合法）；按 `certReq` 决定是否携带证书；签名含 ESS signingCertificate 证书绑定属性。
- 序列号为唯一正整数，持久化于 SQLite（`data/tsa.db`），与 UTC genTime、原始回执同事务提交；签名与记录提交都成功才返回成功，失败不留成功记录；并发不重号，重启续号。
- 系统时钟早于最近一次成功签发时刻时拒绝签发（failInfo = timeNotAvailable），绝不伪造时间。
- 签名在带时限的子进程中执行，临时目录随请求回收。

## 信任范围

演示根 CA 为自签名，仅用于本地/测试信任域。核验方需显式信任 `data/ca.pem`（或 `GET /tsa/chain` 中的根证书）；除此之外不隐含任何公共 PKI 信任。生产使用应替换为受控 CA 签发的 TSA 证书并妥善保管私钥。

## 测试与演示

```bash
.venv/bin/python -m pytest tests/ -q     # 自测
bash scripts/demo.sh                     # 启动服务并用 openssl ts + curl 演示
```

演示覆盖：签发、`openssl ts -verify` 独立离线核验、按序列号取回执、篡改拒绝、未知策略拒绝。

