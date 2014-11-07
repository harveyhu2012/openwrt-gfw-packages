#!/bin/sh

. /lib/functions.sh

rulefile=/var/g.firewall.user

addrules()
{
local domains
local loops
local enabled

config_load gfw-dns
config_get_bool enabled general enabled
config_get loops general loops
config_get domains general domains

[ $enabled -eq 0 ] && return

# wait tail has internet connection
while ! ping -W 1 -c 1 8.8.8.8 >&/dev/null; do sleep 30; done

badip=""

# 确认被污染的域名列表
querydomain=""
matchregex="^${domains//\ /|^}"
for i in $(seq $loops) ; do
	querydomain="$querydomain $domains"
done

# dig每个域名，返回错误的IP。GFW放出的假IP总数有限。
for domain in $domains ; do
	for ip in $(dig +time=1 +tries=1 +retry=0 @$domain $querydomain | grep -E "$matchregex" | grep -o -E "([0-9]+\.){3}[0-9]+") ; do
		if [ -z "$(echo $badip | grep $ip)" ] ; then
			badip="$badip   $ip"
		fi
	done
done

# 建立一个protectdns链，在这个链上丢弃所有被投毒的dns结果包。
echo "iptables -N protectdns" >> $rulefile.tmp 

for ip in $badip ; do
	# 将IP地址转为hex字符串
	hexip=$(printf '%02X ' ${ip//./ }; echo)
	#  --algo bm指明搜索算法。 -m string 搜素字符串（需要安装iptables-mod-filter包）。包的60-500之间搜索IP地址的字符串。搜到的包丢弃。
	echo "iptables -I protectdns -m string --algo bm --hex-string \"|$hexip|\" --from 60 --to 500  -j DROP" >> $rulefile.tmp 
done

# 应该是丢弃返回的空白地址
# 4 & 0x1FFF = 0 应该是表示IPv4的查询? 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 ? 0 >> 22 & 0x3C @ 14 = 0 ?
echo "iptables -I protectdns -m u32 --u32 \"4 & 0x1FFF = 0 && 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 && 0 >> 22 & 0x3C @ 14 = 0\" -j DROP" >> $rulefile.tmp
# -i lo :lo是loop，也就是内部访问。感叹号表示除外。所有INPUT和FORWARD的DNS查询包通过protectdns链。
echo "iptables -I INPUT ! -i lo -p udp --sport 53 -j protectdns" >> $rulefile.tmp
echo "iptables -I FORWARD -p udp --sport 53 -j protectdns" >> $rulefile.tmp

# 文件存在则把新增的行写入，不存在就新建文件
if [[ -s $rulefile ]] ; then
        grep -Fvf $rulefile $rulefile.tmp > $rulefile.action
        cat $rulefile.action >> $rulefile
else
        cp $rulefile.tmp $rulefile
        cp $rulefile.tmp $rulefile.action
fi

. $rulefile.action
rm $rulefile.tmp
rm $rulefile.action
}

delrules()
{
iptables -D INPUT ! -i lo -p udp --sport 53 -j protectdns 2>/dev/null
iptables -D FORWARD -p udp --sport 53 -j protectdns 2>/dev/null
iptables -F protectdns 2>/dev/null
iptables -X protectdns 2>/dev/null
rm $rulefile
}
