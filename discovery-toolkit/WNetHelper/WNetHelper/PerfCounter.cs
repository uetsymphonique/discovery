using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WNetHelper
{
    static class PerfCounter
    {
        // Predefined pseudo-key — never needs RegCloseKey (documented no-op)
        static readonly IntPtr HKEY_PERFORMANCE_DATA = new IntPtr(unchecked((int)0x80000004));

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegQueryValueEx(
            IntPtr hKey, string lpValueName, IntPtr lpReserved,
            out uint lpType, byte[] lpData, ref uint lpcbData);

        static readonly int PTR = IntPtr.Size;

        // PERF_OBJECT_TYPE — offsets after pointer-sensitive LPWSTR fields
        static readonly int OT_NumCounters;
        static readonly int OT_NumInstances;

        // PERF_COUNTER_DEFINITION — offsets after pointer-sensitive LPWSTR fields
        static readonly int CD_CounterType;
        static readonly int CD_CounterSize;
        static readonly int CD_CounterOffset;

        static PerfCounter()
        {
            // PERF_OBJECT_TYPE: 4 DWORDs, LPWSTR, DWORD, LPWSTR, then DWORDs
            int p = 16 + PTR;            // 4 DWORDs + ObjectNameTitle (LPWSTR)
            p += 4;                      // ObjectHelpTitleIndex
            p = Align(p, PTR);           // align for ObjectHelpTitle (LPWSTR)
            p += PTR;                    // ObjectHelpTitle
            OT_NumCounters = p + 4;      // DetailLevel(4) then NumCounters
            OT_NumInstances = p + 12;    // DefaultCounter(4) then NumInstances

            // PERF_COUNTER_DEFINITION: 2 DWORDs, LPWSTR, DWORD, LPWSTR, then DWORDs
            int c = 8 + PTR;             // ByteLength + CounterNameTitleIndex + CounterNameTitle
            c += 4;                      // CounterHelpTitleIndex
            c = Align(c, PTR);           // align for CounterHelpTitle (LPWSTR)
            c += PTR;                    // CounterHelpTitle
            CD_CounterType = c + 8;      // DefaultScale(4) + DetailLevel(4) then CounterType
            CD_CounterSize = c + 12;
            CD_CounterOffset = c + 16;
        }

        static int Align(int v, int a) { return (v + a - 1) & ~(a - 1); }
        static int I32(byte[] b, int o) { return BitConverter.ToInt32(b, o); }

        public static bool Verbose = false;
        static void Log(string msg) { if (Verbose) Console.WriteLine("  [v] " + msg); }

        public static List<string[]> Collect()
        {
            var result = new List<string[]>();

            // Query with growing buffer. HKEY_PERFORMANCE_DATA needs a warm-up call:
            // the first call often returns success with cbData = 0 or ERROR_MORE_DATA.
            byte[] buf = null;
            int dataLen = 0;
            uint bufSize = 1024 * 256;
            int status = -1;

            for (int attempt = 0; attempt < 10; attempt++)
            {
                buf = new byte[bufSize];
                uint cbData = bufSize;
                uint type;
                status = RegQueryValueEx(HKEY_PERFORMANCE_DATA, "230", IntPtr.Zero, out type, buf, ref cbData);
                Log("registry query attempt=" + attempt + " alloc=" + bufSize + " ret=" + status + " used=" + cbData);
                if (status == 0 && cbData > 64)
                {
                    dataLen = (int)cbData;
                    Log("read " + dataLen + " bytes");
                    break;
                }
                if (status != 0 && cbData > bufSize)
                    bufSize = cbData + 8192;   // honor the required size hint
                else
                    bufSize *= 2;
                if (attempt == 9)
                {
                    Log("all attempts returned ret=" + status);
                    return result;
                }
            }

            Log("pointer size=" + PTR
                + " OT_NumCounters=" + OT_NumCounters
                + " OT_NumInstances=" + OT_NumInstances
                + " CD_CounterOffset=" + CD_CounterOffset);

            // PERF_DATA_BLOCK — fixed offsets, no pointer-sensitive fields before the ones we need
            int dbTotalLen = I32(buf, 20);
            int dbHeaderLen = I32(buf, 24);
            int dbNumObjects = I32(buf, 28);
            Log("block: totalLen=" + dbTotalLen + " hdrLen=" + dbHeaderLen + " objects=" + dbNumObjects);

            if (dbNumObjects == 0 || dbHeaderLen < 1 || dbHeaderLen + 128 > dataLen)
            {
                Log("no object data or invalid header length");
                return result;
            }

            // PERF_OBJECT_TYPE
            int objBase = dbHeaderLen;
            int otTotalLen = I32(buf, objBase + 0);
            int otDefLen = I32(buf, objBase + 4);
            int otHdrLen = I32(buf, objBase + 8);
            int otNameIdx = I32(buf, objBase + 12);
            int numCounters = I32(buf, objBase + OT_NumCounters);
            int numInstances = I32(buf, objBase + OT_NumInstances);
            Log("object at " + objBase
                + ": totalLen=" + otTotalLen
                + " defLen=" + otDefLen
                + " hdrLen=" + otHdrLen
                + " titleIdx=" + otNameIdx
                + " fields=" + numCounters
                + " entries=" + numInstances);

            // Walk counter definitions to locate the record-identifier field (title index 784 = "ID Process")
            int idFieldOffset = -1;
            int cOffset = objBase + otHdrLen;
            Log("reading " + numCounters + " field definitions from offset " + cOffset);

            for (int c = 0; c < numCounters; c++)
            {
                if (cOffset + CD_CounterOffset + 4 > dataLen) break;

                int cByteLen = I32(buf, cOffset + 0);
                int cNameIdx = I32(buf, cOffset + 4);
                int cType = I32(buf, cOffset + CD_CounterType);
                int cSize = I32(buf, cOffset + CD_CounterSize);
                int cOff = I32(buf, cOffset + CD_CounterOffset);

                Log("  field[" + c + "] titleIdx=" + cNameIdx
                    + " offset=" + cOff
                    + " size=" + cSize
                    + " type=0x" + cType.ToString("X")
                    + " len=" + cByteLen);

                if (cNameIdx == 784)
                {
                    idFieldOffset = cOff;
                    Log("  >> id field located at offset " + idFieldOffset);
                }

                if (cByteLen <= 0) break;
                cOffset += cByteLen;
            }

            if (idFieldOffset < 0)
                Log("id field (idx 784) not found");

            // Walk instance data
            int instOffset = objBase + otDefLen;
            Log("reading " + numInstances + " entries from offset " + instOffset);

            for (int i = 0; i < numInstances; i++)
            {
                if (instOffset + 24 > dataLen)
                {
                    Log("entry " + i + ": offset " + instOffset + " past end, stopping");
                    break;
                }

                int instByteLen = I32(buf, instOffset + 0);
                int nameOffset = I32(buf, instOffset + 16);
                int nameLength = I32(buf, instOffset + 20);

                string name = "";
                int nameStart = instOffset + nameOffset;
                if (nameLength > 2 && nameStart + nameLength <= dataLen)
                    name = Encoding.Unicode.GetString(buf, nameStart, nameLength - 2);

                int valBlockOffset = instOffset + instByteLen;
                if (valBlockOffset + 4 > dataLen)
                {
                    Log("entry " + i + " '" + name + "': value block at " + valBlockOffset + " past end, stopping");
                    break;
                }
                int valBlockSize = I32(buf, valBlockOffset);

                string id = "";
                if (idFieldOffset >= 0 && valBlockOffset + idFieldOffset + 4 <= dataLen)
                {
                    int idVal = I32(buf, valBlockOffset + idFieldOffset);
                    id = idVal.ToString();
                }

                if (i < 5 || Verbose)
                    Log("entry[" + i + "] name='" + name + "' id=" + id
                        + " at=" + instOffset + " len=" + instByteLen
                        + " valAt=" + valBlockOffset + " valLen=" + valBlockSize);

                result.Add(new string[] { id, name });

                if (valBlockSize <= 0) break;
                instOffset = valBlockOffset + valBlockSize;
            }

            Log("collected " + result.Count + " entries");
            return result;
        }
    }
}
