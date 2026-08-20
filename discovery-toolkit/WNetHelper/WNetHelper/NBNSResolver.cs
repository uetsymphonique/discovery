using System;
using System.Collections.Generic;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace WNetHelper
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct NameEntry
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public char[] ascii_name;
        public UInt16 rr_flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct ResponseHeader
    {
        public UInt16 transaction_id;
        public UInt16 flags;
        public UInt16 question_count;
        public UInt16 answer_count;
        public UInt16 name_service_count;
        public UInt16 additional_record_count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 34)]
        public char[] question_name;
        public UInt16 question_type;
        public UInt16 question_class;
        public UInt32 ttl;
        public UInt16 rdata_length;
        public byte number_of_names;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct ResponseFooter
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] adapter_address;
        public byte version_major;
        public byte version_minor;
        public UInt16 duration;
        public UInt16 frmps_received;
        public UInt16 frmps_transmitted;
        public UInt16 iframe_receive_errors;
        public UInt16 transmit_aborts;
        public UInt32 transmitted;
        public UInt32 received;
        public UInt16 iframe_transmit_errors;
        public UInt16 no_receive_buffer;
        public UInt16 tl_timeouts;
        public UInt16 ti_timeouts;
        public UInt16 free_ncbs;
        public UInt16 ncbs;
        public UInt16 max_ncbs;
        public UInt16 no_transmit_buffers;
        public UInt16 max_datagram;
        public UInt16 pending_sessions;
        public UInt16 max_sessions;
        public UInt16 packet_sessions;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct HostRecord
    {
        public ResponseHeader header;
        public NameEntry[] names;
        public ResponseFooter footer;
        public int is_broken;
    }

    class PacketParser
    {
        public static Exception BrokenPacket = new Exception("Broken Packet");
        public static byte get8(byte[] buff, int offset)
        {
            return buff[offset];
        }

        public static UInt16 get16(byte[] buff, int offset)
        {
            short x = BitConverter.ToInt16(buff, offset);
            return ((UInt16)IPAddress.NetworkToHostOrder(x));
        }

        public static UInt32 get32(byte[] buff, int offset)
        {
            int x = BitConverter.ToInt32(buff, offset);
            return ((UInt32)IPAddress.NetworkToHostOrder(x));
        }

        public static byte[] getBytes(byte[] buff, int offset, int length)
        {
            byte[] _buff = new byte[length];
            Buffer.BlockCopy(buff, offset, _buff, 0, length);
            return _buff;
        }

        public static int getSize(Type clsType, String FieldName)
        {
            FieldInfo f = clsType.GetField(FieldName);
            MarshalAsAttribute ma = (MarshalAsAttribute)Attribute.GetCustomAttribute(f, typeof(MarshalAsAttribute));
            return ma.SizeConst;
        }

        public static char[] getCharArray(byte[] buff, int offset, int length)
        {
            return Encoding.UTF8.GetString(buff, offset, length).ToCharArray();
        }

        public static HostRecord ParseResponse(byte[] buff, int buffsize)
        {
            int offset = 0;
            int size = 0;
            HostRecord HostInfo = new HostRecord();
            ResponseHeader Header = new ResponseHeader();
            NameEntry name = new NameEntry();
            ResponseFooter Footer = new ResponseFooter();

            size = Marshal.SizeOf(Header.transaction_id);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.transaction_id = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.flags);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.flags = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.question_count);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.question_count = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.answer_count);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.answer_count = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.name_service_count);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.name_service_count = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.additional_record_count);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.additional_record_count = get16(buff, offset);
            offset += size;
            size = getSize(typeof(ResponseHeader), "question_name");
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.question_name = getCharArray(buff, offset, size);
            offset += size;
            size = Marshal.SizeOf(Header.question_type);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.question_type = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.question_class);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.question_class = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.ttl);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.ttl = get32(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.rdata_length);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.rdata_length = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Header.number_of_names);
            if (offset + size >= buffsize) throw BrokenPacket;
            Header.number_of_names = get8(buff, offset);
            offset += size;
            HostInfo.header = Header;

            size = Marshal.SizeOf(name) * Header.number_of_names;
            if (offset + size >= buffsize) throw BrokenPacket;
            HostInfo.names = new NameEntry[Header.number_of_names];
            for (int i = 0; i < HostInfo.names.Length; i++)
            {
                NameEntry _name = new NameEntry();
                size = getSize(typeof(NameEntry), "ascii_name");
                _name.ascii_name = getCharArray(buff, offset, size);
                offset += size;
                size = Marshal.SizeOf(name.rr_flags);
                _name.rr_flags = get16(buff, offset);
                offset += size;
                HostInfo.names[i] = _name;
            }

            size = getSize(typeof(ResponseFooter), "adapter_address");
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.adapter_address = getBytes(buff, offset, size);
            offset += size;
            size = Marshal.SizeOf(Footer.version_major);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.version_major = get8(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.version_minor);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.version_minor = get8(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.duration);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.duration = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.frmps_received);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.frmps_received = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.frmps_transmitted);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.frmps_transmitted = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.iframe_receive_errors);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.iframe_receive_errors = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.transmit_aborts);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.transmit_aborts = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.transmitted);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.transmitted = get32(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.received);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.received = get32(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.iframe_transmit_errors);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.iframe_transmit_errors = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.no_receive_buffer);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.no_receive_buffer = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.tl_timeouts);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.tl_timeouts = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.ti_timeouts);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.ti_timeouts = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.free_ncbs);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.free_ncbs = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.ncbs);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.ncbs = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.max_ncbs);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.max_ncbs = get16(buff, offset);
            offset += size;
            size = Marshal.SizeOf(Footer.no_transmit_buffers);
            if (offset + size >= buffsize) throw BrokenPacket;
            Footer.no_transmit_buffers = get16(buff, offset);
            offset += size;

            HostInfo.footer = Footer;

            return HostInfo;
        }

        static Dictionary<string, string> VendorMap = new Dictionary<string, string>()
        {
            { "00-0C-29","Vmware"},
            { "00-50-56","Vmware"},
            { "00-05-69","Vmware"},
            { "00-1C-14","Vmware"},
            { "02-42-AC","Docker"},
            {"00-03-FF","HyperV" },
            {"00-0D-3A","HyperV" },
            {"00-12-5A","HyperV" },
            {"00-15-5D","HyperV" },
            {"00-17-FA","HyperV" },
            {"00-1D-D8","HyperV" },
            {"00-22-48","HyperV" },
            {"00-25-AE","HyperV" },
            {"00-50-F2","HyperV ??" },
            {"44-45-53","HyperV ??" },
            {"7C-ED-8D","HyperV ??" },
            {"00-10-E0","VirtualBox" },
            {"00-14-4F","VirtualBox" },
            {"00-20-F2","VirtualBox" },
            {"00-21-28","VirtualBox" },
            {"00-21-F6","VirtualBox" },
            {"08-00-27","VirtualBox" },
            {"00-1C-42","ParallelsVM" },
            {"00-16-3E","XensourceVM" },
            {"08-00-20","VirtualBox" },
            {"00-50-C2","IEEE ReGi VM" },
       };

        public static string MACParser(byte[] address)
        {
            string Device = "";
            string key = BitConverter.ToString(address, 0, 3);
            if (VendorMap.ContainsKey(key))
                Device = VendorMap[key];
            return Device;
        }
    }
}
