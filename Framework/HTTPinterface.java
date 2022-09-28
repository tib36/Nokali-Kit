package Framework;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * 实现各项操作的函数定义
 * 如GET，POST操作，并处理数据，获取返回值
 * 作者注：正常情况下，二次开发无需修改此页代码
 */


public class HTTPinterface {
    public static void main(){
        System.out.println("[*]DEBUG:Loaded.");
    }
    public static String GET(String inputurl){
        try {
            URL url = new URL(inputurl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.connect();
            InputStream is = connection.getInputStream();
            InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
            BufferedReader br = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String temp;
            while ((temp = br.readLine()) != null) {
                sb.append(temp);
                sb.append(String.format("%n"));
            }
            return sb.toString();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static String POST(String inputurl,String postdata){
        try {
            String targeturl=inputurl;
            URL url=new URL(targeturl);

            HttpURLConnection connection=(HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoInput(true);
            connection.setDoOutput(true);

            connection.connect();
            OutputStreamWriter writer=new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.UTF_8);

            writer.write(postdata);
            writer.flush();
            StringBuilder sbf=new StringBuilder();
            String strRead=null;

            InputStream is=connection.getInputStream();
            BufferedReader reader=new BufferedReader(new InputStreamReader(is));

            while((strRead=reader.readLine())!=null){
                sbf.append(strRead);
                sbf.append(String.format("%n"));
            }
            reader.close();
            connection.disconnect();
            String results=sbf.toString();
            return results;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
