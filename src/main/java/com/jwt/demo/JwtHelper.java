package com.jwt.demo;

import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author  HJH
 * @Description : JWT工具类
 * <br/>参考官网：https://jwt.io/
 * <br/>实现机制参考博客：https://www.cnblogs.com/tyrion1990/p/8134384.html
 * <br/>JWT的数据结构为：A.B.C三部分数据，由字符点"."分割成三部分数据
 * <br/>A-header头信息
 * <br/>B-payload 有效负荷 一般包括：已注册信息（registered claims），公开数据(public claims)，私有数据(private claims)
 * <br/>C-signature 签名信息 是将header和payload进行加密生成的
 * @date  2019/8/2 15:27
 */
public class JwtHelper {

    private static Logger logger = LoggerFactory.getLogger(JwtHelper.class);

    /**
     * @param userId     - 用户编号
     * @param userName   - 用户名
     * @param identities - 客户端信息（变长参数），目前包含浏览器信息，用于客户端拦截器校验，防止跨域非法访问
     * @Author: Helon
     * @deprecated  生成JWT字符串
     * <br/>格式：A.B.C
     * <br/>A-header头信息
     * <br/>B-payload 有效负荷
     * <br/>C-signature 签名信息 是将header和payload进行加密生成的
     * @Data: 2018/7/28 19:26
     * @Modified By:
     */
    public static String generateJWT(String userId, String userName, String... identities) {
        //签名算法，选择SHA-256
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //获取当前系统时间
        long nowTimeMillis = System.currentTimeMillis();
        Date now = new Date(nowTimeMillis);
        //将BASE64SECRET常量字符串使用base64解码成字节数组
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SecretConstant.BASE64SECRET);
        //使用HmacSHA256签名算法生成一个HS256的签名秘钥Key
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        //添加构成JWT的参数
        Map<String, Object> headMap = new HashMap<>();
        /*
            Header
            {
              "alg": "HS256",
              "typ": "JWT"
            }
         */
        headMap.put("alg", SignatureAlgorithm.HS256.getValue());
        headMap.put("typ", "JWT");
        JwtBuilder builder = Jwts.builder().setHeader(headMap)
                /*
                    Payload
                    {
                      "userId": "1234567890",
                      "userName": "John Doe",
                    }
                 */
                //加密后的客户编号
                .claim("userId", AESSecretUtil.encryptToStr(userId, SecretConstant.DATAKEY))
                //客户名称
                .claim("userName", userName)
                //客户端浏览器信息
                .claim("userAgent", identities[0])
                //Signature
                .signWith(signatureAlgorithm, signingKey);
        //添加Token过期时间
        if (SecretConstant.EXPIRESSECOND >= 0) {
            long expMillis = nowTimeMillis + SecretConstant.EXPIRESSECOND;
            Date expDate = new Date(expMillis);
            builder.setExpiration(expDate).setNotBefore(now);
        }
        return builder.compact();
    }

    /**
     * @param jsonWebToken - 页面传过来的token
     * @deprecated: 解析JWT
     * @return Claims对象
     */
    public static Claims parseJWT(String jsonWebToken) {
        Claims claims = null;
        try {
            if (StringUtils.isNotBlank(jsonWebToken)) {
                //解析jwt
                claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SecretConstant.BASE64SECRET))
                        .parseClaimsJws(jsonWebToken).getBody();
            } else {
                logger.warn("[JWTHelper]-json web token 为空");
            }
        } catch (Exception e) {
            logger.error("[JWTHelper]-JWT解析异常：可能因为token已经超时或非法token");
        }
        return claims;
    }

    /**
     * @param jsonWebToken - 页面传过来的token
     * @deprecated: 校验JWT是否有效
     * @return json字符串的demo:<br/>
     * {"freshToken":"A.B.C","userName":"Judy","userId":"123", "userAgent":"xxxx"}
     * <br/>freshToken-刷新后的jwt
     * <br/>userName-客户名称
     * <br/>userId-客户编号
     * <br/>userAgent-客户端浏览器信息
     */
    public static String validateLogin(String jsonWebToken) {
        Map<String, Object> retMap = null;
        Claims claims = parseJWT(jsonWebToken);
        if (claims != null) {
            //解密客户编号
            String decryptUserId = AESSecretUtil.decryptToStr((String) claims.get("userId"), SecretConstant.DATAKEY);
            retMap = new HashMap<>();
            //加密后的客户编号
            retMap.put("userId", decryptUserId);
            //客户名称
            retMap.put("userName", claims.get("userName"));
            //客户端浏览器信息
            retMap.put("userAgent", claims.get("userAgent"));
            //刷新JWT
            retMap.put("freshToken", generateJWT(decryptUserId, (String) claims.get("userName"), (String) claims.get("userAgent"), (String) claims.get("domainName")));
        } else {
            logger.warn("[JWTHelper]-JWT解析出claims为空");
        }
        return retMap != null ? JSONObject.toJSONString(retMap) : null;
    }

    public static void main(String[] args) {
        String jsonWebKey = generateJWT("123", "Judy",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36");
        System.out.println(jsonWebKey);
        Claims claims = parseJWT(jsonWebKey);
        System.out.println(claims);
        System.out.println(validateLogin(jsonWebKey));

    }


}
