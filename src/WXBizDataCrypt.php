<?php

namespace WXBizDataCrypt;

/**
 * 对微信小程序用户加密数据的解密示例代码.
 *
 * @copyright Copyright (c) 1998-2014 Tencent Inc.
 */
class WXBizDataCrypt
{
    private $_appid;
    private $_sessionKey;

    /**
     * 构造函数
     *
     * @param string $sessionKey 用户在小程序登录后获取的会话密钥
     */
    public function __construct($appid, $session_key)
    {
        $this->_appid      = $appid;
        $this->_sessionKey = $session_key;
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文
     *
     * @param string $encrypted_data 加密的用户数据
     * @param string $iv             与用户数据一同返回的初始向量
     * @param string $data           解密后的原文
     *
     * @return int 成功0，失败返回对应的错误码
     */
    public function decryptData($encrypted_data, $iv, &$data)
    {
        if (strlen($this->_sessionKey) != 24) {
            return ErrorCode::$IllegalAesKey;
        }
        
        if (strlen($iv) != 24) {
            return ErrorCode::$IllegalIv;
        }

        $aes_key    = base64_decode($this->_sessionKey);
        $aes_iv     = base64_decode($iv);
        $aes_cipher = base64_decode($encrypted_data);
        $result     = openssl_decrypt($aes_cipher, 'AES-128-CBC', $aes_key, 1, $aes_iv);
        $obj        = json_decode($result);

        if ($obj == null || $obj->watermark->appid != $this->_appid) {
            return ErrorCode::$IllegalBuffer;
        }

        $data = $result;
        return ErrorCode::$OK;
    }
}
