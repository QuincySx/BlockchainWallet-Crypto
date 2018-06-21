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

#### 欢迎给位提设计上的 lssues 和 pr

#### 引入项目 [![](https://jitpack.io/v/QuincySx/BlockchainWallet-Crypto.svg)](https://jitpack.io/#QuincySx/BlockchainWallet-Crypto)

```
allprojects {
  repositories {
    ...
		maven { url 'https://jitpack.io' }
  }
}
  
dependencies {
  implementation 'com.github.QuincySx:BlockchainWallet-Crypto:lase'
}
```

#### 使用说明
[简单使用说明](https://github.com/QuincySx/BlockchainWallet-Crypto/wiki)

## LICENSE
[开源协议](LICENSE)
