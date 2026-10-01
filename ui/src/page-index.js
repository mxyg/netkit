// ★★ 这个文件是**生成的**，别手改 —— 改 app.js，然后跑
//   node scripts/page-index.cjs --write
//   它量的是「哪一页调过哪些工具」「哪一页的正文点名了别页」这两件源码里本来就有的事实。
//   界面拿它做搜索、总览页的能力清单、右侧「这一页用到的工具」；
//   --check 那道闸保证它和 app.js 不漂。
const PAGE_INDEX = {
 "home": {
  "tools": [
   "net.checkup"
  ],
  "refs": [
   "quality",
   "speed",
   "trouble"
  ],
  "cards": []
 },
 "nic": {
  "tools": [
   "net.interfaces",
   "net.routes"
  ],
  "refs": [],
  "cards": [
   {
    "t": "在用的网卡",
    "tools": [
     "net.interfaces"
    ]
   },
   {
    "t": "没在用的网卡",
    "tools": [
     "net.interfaces"
    ]
   },
   {
    "t": "路由表",
    "tools": [
     "net.routes"
    ]
   }
  ]
 },
 "dhcp": {
  "tools": [
   "net.address.set",
   "net.dhcp.bind",
   "net.dhcp.defaults",
   "net.dhcp.events",
   "net.dhcp.leases",
   "net.dhcp.probe",
   "net.dhcp.serve",
   "net.dhcp.setip",
   "net.dhcp.stop",
   "net.interfaces"
  ],
  "refs": [],
  "cards": [
   {
    "t": "把这台电脑变成 DHCP 服务器",
    "tools": [
     "net.address.set",
     "net.dhcp.defaults",
     "net.dhcp.leases",
     "net.dhcp.probe",
     "net.dhcp.serve",
     "net.interfaces"
    ]
   },
   {
    "t": "正在发地址",
    "tools": [
     "net.dhcp.stop"
    ]
   },
   {
    "t": "已接入的设备",
    "tools": [
     "net.dhcp.stop"
    ]
   }
  ]
 },
 "local": {
  "tools": [
   "net.fileshare.serve",
   "net.fileshare.status",
   "net.fileshare.stop",
   "net.port.process"
  ],
  "refs": [],
  "cards": [
   {
    "t": "这个端口被谁占了",
    "tools": [
     "net.port.process"
    ]
   },
   {
    "t": "文件共享（只读）",
    "tools": [
     "net.fileshare.serve",
     "net.fileshare.status",
     "net.fileshare.stop"
    ]
   }
  ]
 },
 "connect": {
  "tools": [
   "net.ping",
   "net.ports.scan",
   "net.tcp.probe",
   "net.udp.probe"
  ],
  "refs": [
   "name",
   "nic",
   "path"
  ],
  "cards": [
   {
    "t": "ping 一个地址",
    "tools": [
     "net.ping",
     "net.tcp.probe"
    ]
   },
   {
    "t": "扫一片端口",
    "tools": [
     "net.ports.scan"
    ]
   },
   {
    "t": "探 UDP 端口",
    "tools": [
     "net.udp.probe"
    ]
   }
  ]
 },
 "path": {
  "tools": [
   "net.mtr",
   "net.mtu.path",
   "net.ping.watch",
   "net.trace"
  ],
  "refs": [
   "connect",
   "name",
   "nic",
   "service"
  ],
  "cards": [
   {
    "t": "路径追踪",
    "tools": [
     "net.trace"
    ]
   },
   {
    "t": "路径质量（逐跳持续探测）",
    "tools": [
     "net.mtr"
    ]
   },
   {
    "t": "连续 ping（看抖不抖）",
    "tools": [
     "net.ping.watch"
    ]
   },
   {
    "t": "路径 MTU",
    "tools": [
     "net.mtu.path"
    ]
   }
  ]
 },
 "name": {
  "tools": [
   "net.dns.query",
   "net.dualstack.check",
   "net.time.check"
  ],
  "refs": [],
  "cards": [
   {
    "t": "DNS 查询",
    "tools": [
     "net.dns.query"
    ]
   },
   {
    "t": "双栈体检",
    "tools": [
     "net.dualstack.check"
    ]
   },
   {
    "t": "校时检查",
    "tools": [
     "net.time.check"
    ]
   }
  ]
 },
 "service": {
  "tools": [
   "net.http.probe",
   "net.tls.check"
  ],
  "refs": [
   "stream"
  ],
  "cards": [
   {
    "t": "网页 / 接口探测",
    "tools": [
     "net.http.probe"
    ]
   },
   {
    "t": "证书检查",
    "tools": [
     "net.tls.check"
    ]
   }
  ]
 },
 "thru": {
  "tools": [
   "net.throughput.serve",
   "net.throughput.status",
   "net.throughput.stop",
   "net.throughput.test"
  ],
  "refs": [],
  "cards": [
   {
    "t": "本机对测口",
    "tools": [
     "net.throughput.serve",
     "net.throughput.status",
     "net.throughput.stop"
    ]
   },
   {
    "t": "打一次对测",
    "tools": [
     "net.throughput.test"
    ]
   }
  ]
 },
 "speed": {
  "tools": [
   "net.speed.test"
  ],
  "refs": [
   "connect"
  ],
  "cards": [
   {
    "t": "量一次公网",
    "tools": [
     "net.speed.test"
    ]
   }
  ]
 },
 "quality": {
  "tools": [
   "net.quality.report",
   "net.quality.status",
   "net.quality.stop",
   "net.quality.watch"
  ],
  "refs": [],
  "cards": [
   {
    "t": "盯一段时间",
    "tools": [
     "net.quality.status",
     "net.quality.stop",
     "net.quality.watch"
    ]
   },
   {
    "t": "这一本账怎么说",
    "tools": [
     "net.quality.report"
    ]
   }
  ]
 },
 "bandwidth": {
  "tools": [
   "net.bandwidth.top"
  ],
  "refs": [
   "local",
   "nic",
   "quality",
   "scan",
   "thru"
  ],
  "cards": [
   {
    "t": "数一会儿，看谁在吃",
    "tools": [
     "net.bandwidth.top"
    ]
   }
  ]
 },
 "scan": {
  "tools": [
   "net.neighbors",
   "net.subnet.scan"
  ],
  "refs": [
   "connect",
   "device"
  ],
  "cards": [
   {
    "t": "扫一个网段",
    "tools": [
     "net.subnet.scan"
    ]
   },
   {
    "t": "本机邻居表",
    "tools": [
     "net.neighbors"
    ]
   }
  ]
 },
 "device": {
  "tools": [
   "net.device.identify",
   "net.discover",
   "net.wol"
  ],
  "refs": [
   "connect",
   "nic",
   "scan"
  ],
  "cards": [
   {
    "t": "问一遍：这些地址是哪台设备",
    "tools": [
     "net.device.identify"
    ]
   },
   {
    "t": "听谁在应答（找没配网的设备）",
    "tools": [
     "net.discover"
    ]
   },
   {
    "t": "Wake-on-LAN 唤醒",
    "tools": [
     "net.wol"
    ]
   }
  ]
 },
 "stream": {
  "tools": [
   "media.gb28181.probe",
   "media.gb28181.register",
   "media.hls.probe",
   "media.onvif.info",
   "media.rtmp.probe",
   "media.rtsp.probe"
  ],
  "refs": [
   "connect"
  ],
  "cards": [
   {
    "t": "问一台 ONVIF 设备",
    "tools": [
     "media.onvif.info"
    ]
   },
   {
    "t": "取流探测",
    "tools": [
     "media.rtsp.probe"
    ]
   },
   {
    "t": "拉一路 HLS（m3u8）",
    "tools": [
     "media.hls.probe"
    ]
   },
   {
    "t": "问一路 RTMP 推流",
    "tools": [
     "media.rtmp.probe"
    ]
   },
   {
    "t": "问一路国标（GB28181）信令",
    "tools": [
     "media.gb28181.probe",
     "media.gb28181.register"
    ]
   }
  ]
 },
 "switch": {
  "tools": [
   "net.snmp.lldp",
   "net.snmp.mac",
   "net.snmp.poe",
   "net.snmp.ports",
   "net.snmp.probe"
  ],
  "refs": [
   "connect"
  ],
  "cards": [
   {
    "t": "这台设备 SNMP 通不通",
    "tools": [
     "net.snmp.probe"
    ]
   },
   {
    "t": "谁插在哪个口（MAC 地址表）",
    "tools": [
     "net.snmp.mac"
    ]
   },
   {
    "t": "这个口到底怎么样（端口表）",
    "tools": [
     "net.snmp.ports"
    ]
   },
   {
    "t": "这个口给不给电（PoE）",
    "tools": [
     "net.snmp.poe"
    ]
   },
   {
    "t": "这根线另一头是谁（LLDP 邻居）",
    "tools": [
     "net.snmp.lldp"
    ]
   },
   {
    "t": "邻居表统计",
    "tools": [
     "net.snmp.lldp"
    ]
   }
  ]
 },
 "topo": {
  "tools": [
   "net.device.identify",
   "net.ping",
   "net.topology.build"
  ],
  "refs": [
   "nic"
  ],
  "cards": [
   {
    "t": "这台在网里的形状",
    "tools": [
     "net.device.identify",
     "net.ping",
     "net.topology.build"
    ]
   }
  ]
 },
 "checkup": {
  "tools": [
   "net.checkup",
   "net.diag.bundle"
  ],
  "refs": [
   "name"
  ],
  "cards": [
   {
    "t": "一键体检",
    "tools": [
     "net.checkup"
    ]
   },
   {
    "t": "导出诊断包",
    "tools": [
     "net.diag.bundle"
    ]
   }
  ]
 },
 "trouble": {
  "tools": [
   "net.troubleshoot"
  ],
  "refs": [
   "connect",
   "dhcp",
   "name",
   "nic",
   "service",
   "stream"
  ],
  "cards": [
   {
    "t": "按症状排查",
    "tools": [
     "net.troubleshoot"
    ]
   }
  ]
 },
 "capture": {
  "tools": [
   "net.capture.flow",
   "net.capture.flows",
   "net.capture.open",
   "net.capture.peer.probe",
   "net.capture.peer.start",
   "net.capture.peer.status",
   "net.capture.peer.stop",
   "net.capture.start",
   "net.capture.status",
   "net.capture.stop",
   "net.interfaces",
   "remote.device.list"
  ],
  "refs": [
   "quality",
   "remote"
  ],
  "cards": [
   {
    "t": "开一路抓包",
    "tools": [
     "net.capture.start",
     "net.capture.status",
     "net.capture.stop",
     "net.interfaces"
    ]
   },
   {
    "t": "这一张流表",
    "tools": [
     "net.capture.flows"
    ]
   },
   {
    "t": "某一条流的明细",
    "tools": [
     "net.capture.flow"
    ]
   },
   {
    "t": "打开一份现成的抓包文件",
    "tools": [
     "net.capture.open"
    ]
   },
   {
    "t": "在对端那台机器上开一路抓包",
    "tools": [
     "net.capture.peer.probe",
     "net.capture.peer.start",
     "net.capture.peer.status",
     "net.capture.peer.stop",
     "remote.device.list"
    ]
   }
  ]
 },
 "remote": {
  "tools": [
   "remote.audit.tail",
   "remote.config.set",
   "remote.device.add",
   "remote.device.list",
   "remote.device.probe",
   "remote.device.remove"
  ],
  "refs": [],
  "cards": [
   {
    "t": "对方可见",
    "tools": [
     "remote.config.set"
    ]
   },
   {
    "t": "登记的设备",
    "tools": [
     "remote.device.probe",
     "remote.device.remove"
    ]
   },
   {
    "t": "登记一台设备",
    "tools": [
     "remote.device.add",
     "remote.device.probe"
    ]
   },
   {
    "t": "审计日志",
    "tools": [
     "remote.audit.tail"
    ]
   }
  ]
 },
 "remote-work": {
  "tools": [
   "remote.desktop.open",
   "remote.device.forget-hostkey",
   "remote.device.list",
   "remote.exec",
   "remote.file.pull",
   "remote.file.push",
   "remote.msg.send",
   "remote.playbook.delete",
   "remote.playbook.list",
   "remote.playbook.run",
   "remote.playbook.save",
   "remote.sessions"
  ],
  "refs": [
   "remote"
  ],
  "cards": [
   {
    "t": "这一页要对哪台干活",
    "tools": []
   },
   {
    "t": "体检剧本",
    "tools": [
     "remote.playbook.delete",
     "remote.playbook.list",
     "remote.playbook.run",
     "remote.playbook.save"
    ]
   }
  ]
 },
 "mobile": {
  "tools": [
   "net.portal.kick",
   "net.portal.rotate",
   "net.portal.start",
   "net.portal.status",
   "net.portal.stop"
  ],
  "refs": [],
  "cards": [
   {
    "t": "手机互联与投屏",
    "tools": [
     "net.portal.kick",
     "net.portal.rotate",
     "net.portal.start",
     "net.portal.status",
     "net.portal.stop"
    ]
   }
  ]
 },
 "tools": {
  "tools": [
   "net.codec.convert",
   "net.mac.analyze",
   "net.mac.random",
   "net.subnet.calc"
  ],
  "refs": [
   "name"
  ],
  "cards": [
   {
    "t": "子网计算",
    "tools": [
     "net.subnet.calc"
    ]
   },
   {
    "t": "MAC 地址",
    "tools": [
     "net.mac.analyze"
    ]
   },
   {
    "t": "随机 MAC",
    "tools": [
     "net.mac.random"
    ]
   },
   {
    "t": "编解码",
    "tools": [
     "net.codec.convert"
    ]
   }
  ]
 }
};
