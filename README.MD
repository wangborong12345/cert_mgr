# cert_mgr

# 功能

列出，安装，移除系统受信任区域证书

# 使用

## 列出
```go
	mgr := cert.NewSystemTrustCertMgr("test_pack")
	list, err := mgr.List()
	if err != nil {
		panic(err)
	}
	for _, certificate := range *list {
		fmt.Print(*certificate.SerialNumber)
	}
```

## 安装
```go
    mgr := cert.NewSystemTrustCertMgr("test_pack")
err := mgr.Install(certificate)
if err != nil {
panic(err)
}

```
## 移除

```go
	mgr := cert.NewSystemTrustCertMgr("test_pack")
	err := mgr.Uninstall(certificate)
	if err != nil {
		panic(err)
	}

```