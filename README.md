# BlockchainWallet-Crypto
[![](https://jitpack.io/v/QuincySx/BlockchainWallet-Crypto.svg)](https://jitpack.io/#QuincySx/BlockchainWallet-Crypto)

#### 简介
##### 这个库到底能干什么
1. 生成比特币公私钥地址
2. 生成以太坊公私钥地址
3. 根据 UTXO 信息打包比特币交易
4. 根据 nonce 信息打包以太坊交易
5. 对比特币交易进行签名
6. 对以太坊交易进行签名
7. 支持 BIP39 助记词
8. 支持 BIP32 子私钥
9. 支持 BIP44 多币种管理
10. 支持 BIP38 加密私钥导入导出
11. 支持以太坊 keystore 导入导出
12. 生成以太坊调用智能合约的参数
13. 生成 EOS 公私钥

#### EOS 从助记词生成私钥
现在 EOS 从助记词生成私钥有两种方式
1. 12 个助记词之间用空格隔开拼接成字符串，然后 Hash 得到私钥
2. 采用 Bip44 标准的生成方案

经过国内大部分钱包商议统一使用第二种方案解决 EOS 从助记词生成私钥的问题

#### 欢迎给位提设计上的 lssues 和 pr

#### 引入项目

```
allprojects {
  repositories {
    ...
		maven { url 'https://jitpack.io' }
  }
}
  
dependencies {
  implementation 'com.github.QuincySx:BlockchainWallet-Crypto:last-version'
}
```

#### 使用说明
[简单使用说明](https://github.com/QuincySx/BlockchainWallet-Crypto/wiki)

## 相关资料
[Bip44 注册币种列表](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)

## LICENSE
[开源协议](LICENSE)
