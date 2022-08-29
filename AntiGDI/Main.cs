//AntiGDI 
//v1.0 (c0d9d by DesConnet)
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Drawing;

namespace AntiGDI
{

    public class ServerInterface : MarshalByRefObject
    {
        public void IsInstalled(int clientPID)
        {
            Console.WriteLine("[INFO] AntiGDI has been injected to {0} process.\r\n", clientPID);
        }

        public void ReportMessages(string[] messages)
        {
            for (int i = 0; i < messages.Length; i++)
            {
                Console.WriteLine(messages[i]);
            }
        }

        public void ReportMessage(string message)
        {
            Console.WriteLine(message);
        }

        public void ReportException(Exception e)
        {
            Console.WriteLine("[ERROR] The target process has reported an error:\r\n" + e.ToString());
        }

        public void Ping()
        {
        }
    }

    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {
        ServerInterface _server = null;

        Queue<string> _messageQueue = new Queue<string>();

        public InjectionEntryPoint(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            _server.Ping();
        }

        public void Run(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());

            // BitBlt
            var BitBltHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "BitBlt"),
                new BitBlt_Delegate(BitBlt_Hook),
                this);

            // StretchBlt
            var StretchBltHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "StretchBlt"),
                new StretchBlt_Delegate(StretchBlt_Hook),
                this);

            // PatBlt
            var PatBltHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "PatBlt"),
                new PatBlt_Delegate(PatBlt_Hook),
                this);

            // PlgBlt
            var PlgBltHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "PlgBlt"),
                new PlgBlt_Delegate(PlgBlt_Hook),
                this);

            // DrawIconEx
            var DrawIconExHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("user32.dll", "DrawIconEx"),
                new DrawIconEx_Delegate(DrawIconEx_Hook),
                this);

            // CreateCompatibleDC
            var CreateCompatibleDCHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "CreateCompatibleDC"),
                new CreateCompatibleDC_Delegate(CreateCompatibleDC_Hook),
                this);

            // CreateCompatibleBitmap
            var CreateCompatibleBitmapHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "CreateCompatibleBitmap"),
                new CreateCompatibleBitmap_Delegate(CreateCompatibleBitmap_Hook),
                this);

            // GetDC
            var GetDCHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("user32.dll", "GetDC"),
                new GetDC_Delegate(GetDC_Hook),
                this);

            // AlphaBlend
            var AlphaBlendHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "GdiAlphaBlend"),
                new AlphaBlend_Delegate(AlphaBlend_Hook),
                this);

            // CreateSolidBrush
            var CreateSolidBrushHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("gdi32.dll", "CreateSolidBrush"),
                new CreateSolidBrush_Delegate(CreateSolidBrush_Hook),
                this);

            BitBltHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            StretchBltHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            PatBltHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            DrawIconExHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            CreateCompatibleDCHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            CreateCompatibleBitmapHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            GetDCHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            AlphaBlendHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            CreateSolidBrushHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("[INFO] All hooks has been installed to this process");
            _server.ReportMessage("[INFO] AntiGDI v1.0 (c0d9d by DesConnet)");

            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                //do nothing
            }

            BitBltHook.Dispose();
            StretchBltHook.Dispose();
            PatBltHook.Dispose();
            PlgBltHook.Dispose();
            DrawIconExHook.Dispose();
            CreateCompatibleDCHook.Dispose();
            CreateCompatibleBitmapHook.Dispose();
            GetDCHook.Dispose();
            AlphaBlendHook.Dispose();
            CreateSolidBrushHook.Dispose();

            EasyHook.LocalHook.Release();
        }

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        //BitBlt
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool BitBlt_Delegate([In] IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight, [In] IntPtr hdcSrc, int nXSrc, int nYSrc, TernaryRasterOperations dwRop);

        [DllImport("gdi32.dll", EntryPoint = "BitBlt", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool BitBlt([In] IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight, [In] IntPtr hdcSrc, int nXSrc, int nYSrc, TernaryRasterOperations dwRop);

        bool BitBlt_Hook([In] IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight, [In] IntPtr hdcSrc, int nXSrc, int nYSrc, TernaryRasterOperations dwRop)
        {
            _server.ReportMessage("[INFO] Process trying to call BitBlt function");
            return false;
        }
        //BitBlt

        //StretchBlt
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool StretchBlt_Delegate(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, TernaryRasterOperations dwRop);

        [DllImport("gdi32.dll")]
        static extern bool StretchBlt(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, TernaryRasterOperations dwRop);

        bool StretchBlt_Hook(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, TernaryRasterOperations dwRop)
        {
            _server.ReportMessage("[INFO] Process trying to call StretchBlt function");
            return false;
        }
        //StretchBlt

        //PatBlt
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool PatBlt_Delegate(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, TernaryRasterOperations dwRop);

        [DllImport("gdi32.dll")]
        static extern bool PatBlt(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, TernaryRasterOperations dwRop);

        bool PatBlt_Hook(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, TernaryRasterOperations dwRop)
        {
            _server.ReportMessage("[INFO] Process trying to call PatBlt function");
            return false;
        }
        //PatBlt

        //PlgBlt
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool PlgBlt_Delegate(IntPtr hdcDest, Point[] lpPoint, IntPtr hdcSrc, int nXSrc, int nYSrc, int nWidth, int nHeight, IntPtr hbmMask, int xMask, int yMask);

        [DllImport("gdi32.dll")]
        static extern bool PlgBlt(IntPtr hdcDest, Point[] lpPoint, IntPtr hdcSrc, int nXSrc, int nYSrc, int nWidth, int nHeight, IntPtr hbmMask, int xMask, int yMask);

        bool PlgBlt_Hook(IntPtr hdcDest, Point[] lpPoint, IntPtr hdcSrc, int nXSrc, int nYSrc, int nWidth, int nHeight, IntPtr hbmMask, int xMask, int yMask)
        {
            _server.ReportMessage("[INFO] Process trying to call PlgBlt function");
            return false;
        }
        //PlgBlt

        //DrawIcon
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool DrawIconEx_Delegate(IntPtr hdc, int xLeft, int yTop, IntPtr hIcon, int cxWidth, int cyHeight, int istepIfAniCur, IntPtr hbrFlickerFreeDraw, int diFlags);

        [DllImport("user32.dll")]
        static extern bool DrawIconEx(IntPtr hdc, int xLeft, int yTop, IntPtr hIcon, int cxWidth, int cyHeight, int istepIfAniCur, IntPtr hbrFlickerFreeDraw, int diFlags);

        bool DrawIconEx_Hook(IntPtr hdc, int xLeft, int yTop, IntPtr hIcon, int cxWidth, int cyHeight, int istepIfAniCur, IntPtr hbrFlickerFreeDraw, int diFlags)
        {
            _server.ReportMessage("[INFO] Process trying to call DrawIconEx function");
            return false;
        }
        //DrawIcon

        //CreateCompatibleDC
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateCompatibleDC_Delegate(IntPtr hdc);

        [DllImport("gdi32.dll")]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        IntPtr CreateCompatibleDC_Hook(IntPtr hdc)
        {
            _server.ReportMessage("[INFO] Process trying to call CreateCompatibleDC function");
            return IntPtr.Zero;
        }
        //CreateCompatibleDC

        //CreateCompatibleBitmap
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateCompatibleBitmap_Delegate(IntPtr hdc, int nWidth, int nHeight);

        [DllImport("gdi32.dll")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

        IntPtr CreateCompatibleBitmap_Hook(IntPtr hdc, int nWidth, int nHeight)
        {
            _server.ReportMessage("[INFO] Process trying to call CreateCompatibleBitmap function");
            return IntPtr.Zero;
        }
        //CreateCompatibleBitmap

        //GetDC
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr GetDC_Delegate(IntPtr hWnd);

        [DllImport("user32.dll")]
        static extern IntPtr GetDC(IntPtr hWnd);

        IntPtr GetDC_Hook(IntPtr hWnd)
        {
            _server.ReportMessage("[INFO] Process trying to call GetDC function");
            return IntPtr.Zero;
        }
        //GetDC

        //AlphaBlend
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool AlphaBlend_Delegate(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, BLENDFUNCTION blendFunction);

        [DllImport("gdi32.dll", EntryPoint = "GdiAlphaBlend")]
        static extern bool AlphaBlend(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, BLENDFUNCTION blendFunction);

        bool AlphaBlend_Hook(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, BLENDFUNCTION blendFunction)
        {
            _server.ReportMessage("[INFO] Process trying to call AlphaBlend function");
            return false;
        }
        //AlphaBlend

        //CreateSolidBrush
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateSolidBrush_Delegate(int crColor);

        [DllImport("gdi32.dll")]
        static extern IntPtr CreateSolidBrush(int crColor);

        IntPtr CreateSolidBrush_Hook(int crColor)
        {
            _server.ReportMessage("[INFO] Process trying to call CreateSolidBrush function");
            return IntPtr.Zero;
        }
        //CreateSolidBrush
    }

    public enum TernaryRasterOperations : uint
    {
        SRCCOPY = 0x00CC0020,
        SRCPAINT = 0x00EE0086,
        SRCAND = 0x008800C6,
        SRCINVERT = 0x00660046,
        SRCERASE = 0x00440328,
        NOTSRCCOPY = 0x00330008,
        NOTSRCERASE = 0x001100A6,
        MERGECOPY = 0x00C000CA,
        MERGEPAINT = 0x00BB0226,
        PATCOPY = 0x00F00021,
        PATPAINT = 0x00FB0A09,
        PATINVERT = 0x005A0049,
        DSTINVERT = 0x00550009,
        BLACKNESS = 0x00000042,
        WHITENESS = 0x00FF0062,
        CAPTUREBLT = 0x40000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BLENDFUNCTION
    {
        byte BlendOp;
        byte BlendFlags;
        byte SourceConstantAlpha;
        byte AlphaFormat;

        public BLENDFUNCTION(byte op, byte flags, byte alpha, byte format)
        {
            BlendOp = op;
            BlendFlags = flags;
            SourceConstantAlpha = alpha;
            AlphaFormat = format;
        }
    }
}
