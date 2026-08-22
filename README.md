# Research-on-user-behavior-privacy-protection-method-for-smart-home

上传的代码分为三部分，以节点命名的文件夹是三种基本流量混淆技术的源代码（节点具体规格如下图所示），matching文件夹是匹配的源代码，trace_classifier-main文件夹是论文“An Input-Agnostic Hierarchical Deep Learning Framework for Traffic Fingerprinting”的源代码。
![image](https://github.com/HiaSop/Research-on-user-behavior-privacy-protection-method-for-smart-home/blob/main/1.jpg)


# 三种基本流量混淆技术

·数据包填充

  涉及2个节点（192.168.2.21和192.168.2.22）
  
  以下行流量为例，192.168.2.21将服务器至设备方向的流量填充，192.168.2.22用于恢复；反过来另一个方向，192.168.2.22将服务器至设备方向的流量填充，192.168.2.21用于恢复。

  
·数据包分割

  涉及2个节点（192.168.2.21和192.168.2.22）
  
  以下行流量为例，192.168.2.21将服务器至设备方向的流量分割；反过来另一个方向，192.168.2.22将服务器至设备方向的流量分割。

  
·虚假流量注入

  涉及4个节点（192.168.2.2、192.168.2.21、192.168.2.22和192.168.2.5）
  
  192.168.2.21作为服务器，192.168.2.5作为设备端，根据历史设备流量合成特征一致的流量，模拟双向通信
  
  以下行流量为例，192.168.2.21将服务器至设备方向的合成流量的IP进行修改，将设备至服务器方向的合成流量的IP进行恢复；反过来另一个方向，192.168.2.22将设备至服务器方向的合成流量的IP进行修改，将服务器至设备方向的合成流量的IP进行恢复。
  
# matching

基于签名匹配设备事件

# trace_classifier-main

基于深度学习分类方法
