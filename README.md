# Shadowrocket Pro Config

个人 Shadowrocket 配置：直连域名使用系统 DNS，代理域名通过代理使用加密 DoH，并保留 IPv6、HTTPDNS 防泄露和服务分流。

## 使用地址

```text
https://raw.githubusercontent.com/wxk40899-sys/shadowrocket-config/main/output/Shadowrocket-Pro.conf
```

在 Shadowrocket 中导入上述地址即可。配置内的 `update-url` 也指向同一文件。

## 自动更新流程

GitHub Actions 每天自动执行，也支持在 Actions 页面手动运行：

1. 下载最新版上游 `lazy_group.conf`。
2. 保留上游的通用参数说明、兼容性设置、Host、URL Rewrite 和 MITM。
3. 从 `config/policy.conf` 注入锁定的个人 DNS、IPv6、策略组和规则。
4. 校验策略引用、规则顺序、DNS 模式、IPv6、远程规则地址和最终兜底。
5. 只有生成结果变化且全部检查通过时，才更新输出文件。

检查失败时不会提交新配置，因此 Shadowrocket 会继续使用上一份正常版本。

## 配置原则

- 直连域名：系统 DNS，不加密。
- 代理域名：Cloudflare DoH，经代理；失败后使用 Google DoH，经代理。
- 代理 DNS 不允许回退到系统 DNS。
- IPv6 开启，双栈连接不强制优先 IPv6。
- 不绑定节点名称或订阅名称，默认使用 `PROXY`。
- 不包含银行、证券或券商专属规则。
- 已知 App HTTPDNS 默认由“DNS 防泄露”策略拒绝。

## 文件说明

- `config/policy.conf`：个人策略模板，是需要长期维护的核心文件。
- `output/Shadowrocket-Pro.conf`：自动生成、供 Shadowrocket 订阅的成品。
- `scripts/build_config.py`：从上游生成配置。
- `scripts/validate_config.py`：发布前的严格检查。
- `.github/workflows/update-config.yml`：定时及手动更新任务。

不要向仓库提交节点密码、订阅链接、MITM 私钥或其他敏感信息。
