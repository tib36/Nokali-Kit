import Module.TP5_5023method_RCE;
import Module.TP5_invokefunction_RCE;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * 作者：Nokali
 * 主程序，包含图形界面操作，以及调用各模块
 */

public class Main {
    public static void main(String[] args) {
        //--------------------------------------------------------
        //绘制图形用户界面
        JFrame f = new JFrame("NokaliAttackFramework");
        f.setSize(570, 550);
        f.setLocation(200, 200);
        f.setLayout(null);    //程序主窗体
        try {
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
            //如上设置为Nimbus主题，如果需要切换回默认主题，注释该行即可。
        }catch (Exception e){
            System.out.println("[-]ERROR.");
            e.printStackTrace();
        }

        String[] exp= new String[]{
                "TP5_invokefunction_RCE",
                "TP5_5023method_RCE",
                "Test"
        };
        JComboBox explist=new JComboBox(exp);
        explist.setBounds(20,25,200,30);

        JLabel target_label = new JLabel("URL:");
        JTextField target_text = new JTextField("");
        target_label.setBounds(30, 120, 50, 30);
        target_text.setBounds(80, 120, 250, 30);    //URL提示标签和URL输入框

        JButton submit = new JButton("一键检测");
        submit.setBounds(350, 120, 120, 30);
        JTextArea output = new JTextArea("");
        output.setLineWrap(true);
        JScrollPane scroll = new JScrollPane(output);
        scroll.setBounds(30, 220, 450, 250);
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);    //检测按钮和输出结果文本框

        JLabel cmd_label = new JLabel("CMD:");
        JTextField cmd_text = new JTextField("");
        cmd_label.setBounds(30, 170, 50, 30);
        cmd_text.setBounds(80, 170, 250, 30);    //执行命令提示标签和命令输入框

        JButton execute = new JButton("一键利用");
        execute.setBounds(350, 170, 120, 30);

        f.add(explist);
        f.add(target_label);
        f.add(target_text);
        f.add(cmd_label);
        f.add(cmd_text);
        f.add(submit);
        f.add(scroll);
        f.add(execute);    //绘制各组件

        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setVisible(true);
        //图形界面绘制完成
        //--------------------------------------------------------

        submit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                switch (explist.getSelectedItem().toString()) {
                    case "TP5_invokefunction_RCE" -> {
                        output.append("[*]执行TP5_invokefunction_RCE模块中，执行模式为：检测");
                        output.append(String.format("%n"));
                        Boolean result;
                        String targeturl=target_text.getText();
                        result= TP5_invokefunction_RCE.check(targeturl);
                        if(result){
                            output.append("[+]检测成功，目标存在远程命令执行漏洞");
                        }else{
                            output.append("[-]未检测到漏洞");
                        }
                        output.append(String.format("%n"));
                    }
                    case "TP5_5023method_RCE" -> {
                        output.append("[*]执行TP5_5023method_RCE模块中，执行模式为：检测");
                        output.append(String.format("%n"));
                        Boolean result;
                        String targeturl=target_text.getText();
                        result= TP5_5023method_RCE.check(targeturl);
                        if(result){
                            output.append("[+]检测成功，目标存在远程命令执行漏洞");
                        }else{
                            output.append("[-]未检测到漏洞");
                        }
                        output.append(String.format("%n"));
                    }
                    case "Test" -> {
                        output.append("[*]Test.");
                        output.append(String.format("%n"));
                    }
                    default -> {
                        output.append("[-]ERROR.");
                        output.append(String.format("%n"));
                    }
                }
            }
        });

        execute.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                switch (explist.getSelectedItem().toString()){
                    case "TP5_invokefunction_RCE" -> {
                        output.append("[*]执行TP5_invokefunction_RCE模块中，执行模式为：利用");
                        output.append(String.format("%n"));
                        String result;
                        String targeturl=target_text.getText();
                        String cmd=cmd_text.getText();
                        result= TP5_invokefunction_RCE.exploit(targeturl,cmd);
                        output.append("[+]命令执行回显：");
                        output.append(String.format("%n"));
                        output.append(result);
                        output.append(String.format("%n"));
                    }
                    case "TP5_5023method_RCE" -> {
                        output.append("[*]执行TP5_5023method_RCE模块中，执行模式为：利用");
                        output.append(String.format("%n"));
                        String result;
                        String targeturl=target_text.getText();
                        String cmd=cmd_text.getText();
                        result= TP5_5023method_RCE.exploit(targeturl,cmd);
                        output.append("[+]命令执行回显：");
                        output.append(String.format("%n"));
                        output.append(result);
                        output.append(String.format("%n"));
                    }
                }
            }
        });

    }
}
