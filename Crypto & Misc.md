## Crypto & Misc

[TOC]

### Picture

Kali Linux下用Steghide分析一下nogamenolife.jpg，发现图片中藏了一个RAR：

![Screen Shot 2019-01-20 at 4.37.34 PM](https://ws2.sinaimg.cn/large/006tNc79gy1fzd54owbquj31ay08i0wc.jpg)

用binwalk的-e命令或者windows下winhex等软件分离出rar文件。

![Screen Shot 2019-01-20 at 4.42.22 PM](https://ws3.sinaimg.cn/large/006tNc79gy1fzd567wejkj31as08y43u.jpg)

将RAR文件解压，得到一个png一个txt。

![Screen Shot 2019-01-20 at 4.44.23 PM](https://ws2.sinaimg.cn/large/006tNc79gy1fzd57jqtalj30wi0bajtb.jpg)

一看png文件名，可知要用lsb隐写。拖到stegsolve里面研究一下，啥也没发现。

结合password.txt分析，考虑原图可能是用专门隐写工具加密的。遂寻找其他png隐写工具，发现一款cloacked-pixel。该工具引用Crypto库，使用python2.7在terminal中执行：（python3.x下需特殊配置）

`python2.7 lsb.py extract lsb-stego.png result hustctf`

![Screen Shot 2019-01-21 at 9.08.12 AM](https://ws1.sinaimg.cn/large/006tNc79ly1fzdxnfwiscj30vo038tae.jpg)

winhex打开result文件，发现`52617221`的文件头，经查询可知对应rar文件。

![Screen Shot 2019-01-21 at 9.15.50 AM](https://ws3.sinaimg.cn/large/006tNc79ly1fzdxv5hw84j30hk044aad.jpg)加.rar后缀解压得txt文件，flag在其中。

**flag{l3h_no_game_no_life}**

------

### Traffic1

**先看tip：**

> tip1:对Rar文件头的十六进制数要敏感
>
> tip2:密码在流量包中（HTTP）
>
> \- .... . ..--.- .--. .- ... ... .-- --- .-. -.. ..--.- .. ... ..--.- . -. -.-. .-. -.-- .--. - . -.. ..--.- -... -.-- ..--.- .--- ... ..-. ..- -.-. -.-

**Tip分析：**

Tip1 rar的文件头为`52617221`,上一道图片隐写题最后也用到了。

Tip2 暂时没什么用

Tip最后面那串摩尔斯电码解密得`THE_PASSWORD_IS_ENCRYPTED_BY_JSFUCK`，说明密码是由JSFUCK这种编码方式加密而成的。不妨称之为Tip3



打开secret.log，表面一堆乱码和英文字符（貌似是三星Galaxy C5的设备信息）穿插在一起，定睛一瞧中间有一组数字串，开头是52617221，tip1用上了。

![](https://ws1.sinaimg.cn/large/006tNc79ly1fze0klkdmej310205uae9.jpg)

用winhex将数字串保存为一个rar，发现rar里面有个flag.txt，看来方向没错，只不过flag.txt上了密码，还得费一番功夫。

回过头来看tip2，使用wireshark打开流量包找密码，检索区间为http协议。密码构成方式呢，应该是`()+[]!`这六个字符，也就是JSFUCK编码。tip3这样一来也用上了。

Wireshark过滤出http协议，没翻多久就找到了一堆括号加号感叹号（不得不说jsfuck太明显了）

![](https://ws4.sinaimg.cn/large/006tNc79ly1fze0m8ankfj31c00u0nkr.jpg)



chrome随便开一网页，F12->Console->将JSFUCK代码输进去->Enter,弹窗中弹出解密后文本（也即是我们想要的密码）。

![](https://ws1.sinaimg.cn/large/006tNc79ly1fze1c6kv0ej30ow07cgm2.jpg)

或者`http://www.jsfuck.com`网站也可完成JSFUCK解密。

有了压缩包密码，解压flag.txt即得flag。

**flag{l3h_tr4_ffic_4n4_lys3}**

------

### Misc

使用VMware Workstation试图打开虚拟机文件，发现要密码。在tip.docx中寻找灵感，什么有用信息都没有。考虑到Word可作为信息隐藏的载体，遂MS Word依次点击文件->选项->显示，将“隐藏文字”处打勾，发现隐藏的虚拟机密码`hust123`。

![捕获](https://ws1.sinaimg.cn/large/006tNc79ly1fzfrpscyg5j30oo0i5gu0.jpg)

大大的表情包摆在那里，以为有什么名堂。把表情包从word里提取出来放stegsolve和steghide里检测，一无所获。

使用密码`hust123`登进虚拟机，发现还要输Linux用户名和密码。但我不知道啊！用常见的root，admin之类的配上hust123混搭了一下发现不行，遂放弃，另寻出路。到最后我才明白，此乃障眼法。根本无需实际登陆进linux系统，因为vmdk文件本身就是信息隐藏的绝佳载体。

直接上winhex，搜索flag、txt、ctf等字样，最终在搜索flag.txt时在`Ubuntu 64 位-s005.vmdk`中发现有flag.txt和success.txt两文件藏在一个zip包中。（zip文件头`504B0304` 文件尾`504B0506`）。将该zip文件Paste Into New File，另存为zip格式，用密码`hust123`（原来是干这个用的）解压zip即得最终flag。

![捕获1](https://ws1.sinaimg.cn/large/006tNc79ly1fzfrpesbf6j31ol0fqac4.jpg)

**flag{hust_St3_g4n0_gr4_phy}**