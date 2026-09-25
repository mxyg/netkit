package capture

// 造大端参照件用的脚手架。
//
// ★ 为什么不拿小端那份整体翻字节序：块里既有 32 位字段（类型、总长、时间戳），也有
//   两个 16 位字段并排的选项头（码、长）。按 4 字节整块翻，恰好把「码」和「长」也换了位置，
//   造出来的是一份谁都不写的假文件 —— 拿它测出来的「读得开」不算数。
//   这里按规范逐字段写大端，才是真·那头写的文件。

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

type beOptions struct {
	iface Interface
	ts    time.Time
	data  []byte
	orig  int
}

// beFile 按规范逐字段写一份大端 pcapng：段头 + 一条接口描述 + 一个包。
func beFile(t *testing.T, o beOptions) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(beBlock(t, blockSHB, func(x *bytes.Buffer) {
		be32(x, byteOrderMagic)
		be16(x, 1) // 主版本
		be16(x, 0) // 次版本
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], ^uint64(0))
		x.Write(l[:])
	}, nil))

	// 接口描述：口名走 if_name 选项，正好把「码 + 长」那两个 16 位并排的情况逼出来。
	var idbOpts []option
	if o.iface.Name != "" {
		idbOpts = append(idbOpts, option{code: optIfaceName, value: []byte(o.iface.Name)})
	}
	if u := o.iface.tsUnit; u != 0 && u != DefaultTSUnit {
		// 刻度不是缺省就得写 if_tsresol，否则读侧按微秒解，时间戳整条压平一千倍。
		idbOpts = append(idbOpts, option{code: optIfaceTSResol, value: []byte{tsResolByte(u)}})
	}
	b.Write(beBlock(t, blockIDB, func(x *bytes.Buffer) {
		be16(x, o.iface.LinkType)
		be16(x, 0) // Reserved
		be32(x, o.iface.SnapLen)
	}, idbOpts))

	ticks := ticksFor(o.iface.TSUnit(), o.ts)
	b.Write(beBlock(t, blockEPB, func(x *bytes.Buffer) {
		be32(x, 0) // 口 0
		be32(x, uint32(ticks>>32))
		be32(x, uint32(ticks))
		be32(x, uint32(len(o.data)))
		be32(x, uint32(o.orig))
		x.Write(o.data)
		x.Write(make([]byte, paddedLen(len(o.data))-len(o.data)))
	}, nil))
	return b.Bytes()
}

// beBlock 拼一个大端块：定长正文由 body 写，选项按「码 2 + 长 2 + 值 + 补零」写。
func beBlock(t *testing.T, typ uint32, body func(*bytes.Buffer), opts []option) []byte {
	t.Helper()
	var inner bytes.Buffer
	body(&inner)
	var optBytes bytes.Buffer
	for _, o := range opts {
		be16(&optBytes, o.code)
		be16(&optBytes, uint16(len(o.value)))
		optBytes.Write(o.value)
		optBytes.Write(make([]byte, paddedLen(len(o.value))-len(o.value)))
	}
	optBytes.Write([]byte{0, 0, 0, 0}) // 选项表结束
	total := uint32(8 + inner.Len() + optBytes.Len() + 4)
	var out bytes.Buffer
	be32(&out, typ)
	be32(&out, total)
	out.Write(inner.Bytes())
	out.Write(optBytes.Bytes())
	be32(&out, total)
	if out.Len() != int(total) {
		t.Fatalf("造的块 %d 字节，自称 %d —— 脚手架自己就先错了", out.Len(), total)
	}
	return out.Bytes()
}

func be32(w io.Writer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, _ = w.Write(b[:])
}

func be16(w io.Writer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, _ = w.Write(b[:])
}
