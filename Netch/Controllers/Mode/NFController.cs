using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Netch.Models;
using Netch.Utils;
using nfapinet;

namespace Netch.Controllers
{
    public class NFController : ModeController
    {
        private static readonly ServiceController NFService = new ServiceController("netfilter2");

        private static readonly string BinDriver = string.Empty;
        private static readonly string SystemDriver = $"{Environment.SystemDirectory}\\drivers\\netfilter2.sys";
        private static string[] _sysDns = { };

        static NFController()
        {
            switch ($"{Environment.OSVersion.Version.Major}.{Environment.OSVersion.Version.Minor}")
            {
                case "10.0":
                    BinDriver = "Win-10.sys";
                    break;
                case "6.3":
                case "6.2":
                    BinDriver = "Win-8.sys";
                    break;
                case "6.1":
                case "6.0":
                    BinDriver = "Win-7.sys";
                    break;
                default:
                    Logging.Error($"不支持的系统版本：{Environment.OSVersion.Version}");
                    return;
            }

            BinDriver = "bin\\" + BinDriver;
        }

        public NFController()
        {
            Name = "Redirector";
            MainFile = "Redirector.exe";
            StartedKeywords("Redirect TCP to");
            StoppedKeywords("Failed", "Unable");
        }

        /*
        public override bool Start(Server server, Mode mode)
        {
            Logging.Info("内置驱动版本: " + DriverVersion(BinDriver));
            if (DriverVersion(SystemDriver) != DriverVersion(BinDriver))
            {
                if (File.Exists(SystemDriver))
                {
                    Logging.Info("系统驱动版本: " + DriverVersion(SystemDriver));
                    Logging.Info("更新驱动");
                    UninstallDriver();
                }

                if (!InstallDriver())
                    return false;
            }

            var processList = "";
            foreach (var proc in mode.Rule)
                processList += proc + ",";
            processList += "NTT.exe";

            Instance = GetProcess();
            if (server.Type != "Socks5")
            {
                Instance.StartInfo.Arguments += $"-r 127.0.0.1:{Global.Settings.Socks5LocalPort} -p \"{processList}\"";
            }

            else
            {
                var result = DNS.Lookup(server.Hostname);
                if (result == null)
                {
                    Logging.Info("无法解析服务器 IP 地址");
                    return false;
                }

                Instance.StartInfo.Arguments += $"-r {result}:{server.Port} -p \"{processList}\"";
                if (!string.IsNullOrWhiteSpace(server.Username) && !string.IsNullOrWhiteSpace(server.Password)) Instance.StartInfo.Arguments += $" -username \"{server.Username}\" -password \"{server.Password}\"";
            }

            Instance.StartInfo.Arguments += $" -t {Global.Settings.RedirectorTCPPort}";
            Instance.OutputDataReceived += OnOutputDataReceived;
            Instance.ErrorDataReceived += OnOutputDataReceived;

            for (var i = 0; i < 2; i++)
            {
                State = State.Starting;
                Instance.Start();
                Instance.BeginOutputReadLine();
                Instance.BeginErrorReadLine();

                for (var j = 0; j < 40; j++)
                {
                    Thread.Sleep(250);

                    if (State == State.Started)
                    {
                        if (Global.Settings.ModifySystemDNS)
                        {
                            //备份并替换系统DNS
                            _sysDns = DNS.getSystemDns();
                            string[] dns = {"1.1.1.1", "8.8.8.8"};
                            DNS.SetDNS(dns);
                        }

                        return true;
                    }
                }

                Logging.Error(Name + " 启动超时");
                Stop();
                if (!RestartService()) return false;
            }

            return false;
        }
        */

        public override bool Start(Server server, Mode mode)
        {
            Logging.Info("内置驱动版本: " + DriverVersion(BinDriver));
            if (DriverVersion(SystemDriver) != DriverVersion(BinDriver))
            {
                if (File.Exists(SystemDriver))
                {
                    Logging.Info("系统驱动版本: " + DriverVersion(SystemDriver));
                    Logging.Info("更新驱动");
                    UninstallDriver();
                }

                if (!InstallDriver())
                    return false;
            }

            //代理进程
            var processes = "";
            //IP过滤
            var processesIPFillter = "";

            //开启进程白名单模式
            if (!Global.Settings.ProcessWhitelistMode)
                processes += "NTT.exe,";

            foreach (var proc in mode.Rule)
            {
                //添加进程代理
                if (proc.EndsWith(".exe"))
                    processes += proc + ",";
                else
                    //添加IP过滤器
                    processesIPFillter += proc + ",";
            }

            var argStr = "";

            if (server.Type != "Socks5")
            {
                argStr += $"-rtcp 127.0.0.1:{Global.Settings.Socks5LocalPort}";
                if (!StartUDPServerAndAppendToArgument(ref argStr))
                    return false;
            }
            else
            {
                var result = DNS.Lookup(server.Hostname);
                if (result == null)
                {
                    Logging.Error("无法解析服务器 IP 地址");
                    return false;
                }

                argStr += $"-rtcp {result}:{server.Port}";

                if (!string.IsNullOrWhiteSpace(server.Username) && !string.IsNullOrWhiteSpace(server.Password))
                    argStr += $" -username \"{server.Username}\" -password \"{server.Password}\"";

                if (Global.Settings.UDPServer)
                {
                    if (Global.Settings.UDPServerIndex == -1)
                    {
                        argStr += $" -rudp {result}:{server.Port}";
                    }
                    else
                    {
                        if (!StartUDPServerAndAppendToArgument(ref argStr))
                            return false;
                    }
                }
                else
                {
                    argStr += $" -rudp {result}:{server.Port}";
                }
            }

            //开启进程白名单模式
            argStr += $" -bypass {Global.Settings.ProcessWhitelistMode.ToString().ToLower()}";
            if (Global.Settings.ProcessWhitelistMode)
                processes += Firewall.ProgramPath.Aggregate(string.Empty, (current, file) => current + Path.GetFileName(file) + ",");
            
            if (processes.EndsWith(","))
                processes = processes.Substring(0,processes.Length - 1);
            argStr += $" -p \"{processes}\"";

            // true  除规则内IP全走代理
            // false 仅代理规则内IP
            if (processesIPFillter.EndsWith(","))
            {
                processesIPFillter = processesIPFillter.Substring(0,processesIPFillter.Length - 1);
                argStr += $" -bypassip {mode.ProcesssIPFillter.ToString().ToLower()}";
                argStr += $" -fip \"{processesIPFillter}\"";
            }
            else
            {
                argStr += " -bypassip true";
            }

            //进程模式代理IP日志打印
            argStr += $" -printProxyIP {Global.Settings.ProcessProxyIPLog.ToString().ToLower()}";

            //开启进程UDP代理
            argStr += $" -udpEnable {(!Global.Settings.ProcessNoProxyForUdp).ToString().ToLower()}";

            argStr += " -dlog";

            Logging.Info($"Redirector : {argStr}");

            Instance = GetProcess();
            Instance.StartInfo.Arguments = argStr;
            Instance.OutputDataReceived += OnOutputDataReceived;
            Instance.ErrorDataReceived += OnOutputDataReceived;

            for (var i = 0; i < 2; i++)
            {
                State = State.Starting;
                Instance.Start();
                Instance.BeginOutputReadLine();
                Instance.BeginErrorReadLine();

                for (var j = 0; j < 40; j++)
                {
                    Thread.Sleep(250);

                    if (State == State.Started)
                    {
                        if (Global.Settings.ModifySystemDNS)
                        {
                            //备份并替换系统DNS
                            _sysDns = DNS.getSystemDns();
                            string[] dns = {"1.1.1.1", "8.8.8.8"};
                            DNS.SetDNS(dns);
                        }

                        return true;
                    }
                }

                Logging.Error(Name + " 启动超时");
                Stop();
                if (!RestartService()) return false;
            }

            return false;
        }

        private bool RestartService()
        {
            try
            {
                switch (NFService.Status)
                {
                    // 启动驱动服务
                    case ServiceControllerStatus.Running:
                        // 防止其他程序占用 重置 NF 百万连接数限制
                        NFService.Stop();
                        NFService.WaitForStatus(ServiceControllerStatus.Stopped);
                        Global.MainForm.StatusText(i18N.Translate("Starting netfilter2 Service"));
                        NFService.Start();
                        break;
                    case ServiceControllerStatus.Stopped:
                        Global.MainForm.StatusText(i18N.Translate("Starting netfilter2 Service"));
                        NFService.Start();
                        break;
                }
            }
            catch (Exception e)
            {
                Logging.Error("启动驱动服务失败：\n" + e);

                var result = NFAPI.nf_registerDriver("netfilter2");
                if (result != NF_STATUS.NF_STATUS_SUCCESS)
                {
                    Logging.Error($"注册驱动失败，返回值：{result}");
                    return false;
                }

                Logging.Info("注册驱动成功");
            }

            return true;
        }

        public static string DriverVersion(string file)
        {
            return File.Exists(file) ? FileVersionInfo.GetVersionInfo(file).FileVersion : string.Empty;
        }

        /// <summary>
        ///     卸载 NF 驱动
        /// </summary>
        /// <returns>是否成功卸载</returns>
        public static bool UninstallDriver()
        {
            Global.MainForm.StatusText(i18N.Translate("Uninstalling NF Service"));
            Logging.Info("卸载 NF 驱动");
            try
            {
                if (NFService.Status == ServiceControllerStatus.Running)
                {
                    NFService.Stop();
                    NFService.WaitForStatus(ServiceControllerStatus.Stopped);
                }
            }
            catch (Exception)
            {
                // ignored
            }

            if (!File.Exists(SystemDriver)) return true;

            try
            {
                NFAPI.nf_unRegisterDriver("netfilter2");
            }
            catch (Exception e)
            {
                Logging.Error(e.ToString());
                return false;
            }

            File.Delete(SystemDriver);
            return true;
        }

        /// <summary>
        ///     安装 NF 驱动
        /// </summary>
        /// <returns>驱动是否安装成功</returns>
        public static bool InstallDriver()
        {
            Logging.Info("安装 NF 驱动");
            try
            {
                File.Copy(BinDriver, SystemDriver);
            }
            catch (Exception e)
            {
                Logging.Error("驱动复制失败\n" + e);
                return false;
            }

            Global.MainForm.StatusText(i18N.Translate("Register driver"));
            // 注册驱动文件
            var result = NFAPI.nf_registerDriver("netfilter2");
            if (result == NF_STATUS.NF_STATUS_SUCCESS)
            {
                Logging.Info($"驱动安装成功");
            }
            else
            {
                Logging.Error($"注册驱动失败，返回值：{result}");
                return false;
            }

            return true;
        }

        // private new void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
        // {
        //     if (!Write(e.Data)) return;
        //     if (State == State.Starting)
        //     {
        //         if (Instance.HasExited)
        //             State = State.Stopped;
        //         else if (e.Data.Contains("Started"))
        //             State = State.Started;
        //         else if (e.Data.Contains("Failed") || e.Data.Contains("Unable")) State = State.Stopped;
        //     }
        //     else if (State == State.Started)
        //     {
        //         if (e.Data.StartsWith("[APP][Bandwidth]"))
        //         {
        //             var splited = e.Data.Replace("[APP][Bandwidth]", "").Trim().Split(',');
        //             if (splited.Length == 2)
        //             {
        //                 var uploadSplited = splited[0].Split(':');
        //                 var downloadSplited = splited[1].Split(':');
        //
        //                 if (uploadSplited.Length == 2 && downloadSplited.Length == 2)
        //                     if (long.TryParse(uploadSplited[1], out var upload) && long.TryParse(downloadSplited[1], out var download))
        //                         Task.Run(() => OnBandwidthUpdated(upload, download));
        //             }
        //         }
        //     }
        // }

        public override void Stop()
        {
            Task.Run(() =>
            {
                if (Global.Settings.ModifySystemDNS)
                    //恢复系统DNS
                    DNS.SetDNS(_sysDns);
            });
            StopInstance();
            try
            {
                if (UDPServerInstance == null || UDPServerInstance.HasExited) return;
                UDPServerInstance.Kill();
                UDPServerInstance.WaitForExit();
            }
            catch (Exception e)
            {
                Logging.Error($"停止 {MainFile}.exe 错误：\n" + e);
            }
        }

        /// <summary>
        ///     流量变动事件
        /// </summary>
        public event BandwidthUpdateHandler OnBandwidthUpdated;

        /// <summary>
        ///     流量变动处理器
        /// </summary>
        /// <param name="upload">上传</param>
        /// <param name="download">下载</param>
        public delegate void BandwidthUpdateHandler(long upload, long download);

        /// <summary>
        ///     UDP代理进程实例
        /// </summary>
        public Process UDPServerInstance;

        private bool StartUDPServerAndAppendToArgument(ref string fallback)
        {
            if (Global.Settings.UDPServer)
            {
                if (Global.Settings.UDPServerIndex == -1)
                {
                    fallback += $" -rudp 127.0.0.1:{Global.Settings.Socks5LocalPort}";
                }
                else
                {
                    Models.Server UDPServer = Global.Settings.Server.AsReadOnly()[Global.Settings.UDPServerIndex];

                    var result = Utils.DNS.Lookup(UDPServer.Hostname);
                    if (result == null)
                    {
                        Logging.Error("无法解析服务器 IP 地址");
                        return false;
                    }

                    var UDPServerHostName = result.ToString();

                    if (UDPServer.Type != "Socks5")
                    {
                        //启动UDP分流服务支持SS/SSR/Trojan
                        if (UDPServer.Type == "SS")
                        {
                            UDPServerInstance = GetProcess("bin\\Shadowsocks.exe");
                            UDPServerInstance.StartInfo.Arguments = $"-s {UDPServerHostName} -p {UDPServer.Port} -b {Global.Settings.LocalAddress} -l {Global.Settings.Socks5LocalPort + 1} -m {UDPServer.EncryptMethod} -k \"{UDPServer.Password}\" -u";
                        }

                        if (UDPServer.Type == "SSR")
                        {
                            UDPServerInstance = GetProcess("bin\\ShadowsocksR.exe");
                            UDPServerInstance.StartInfo.Arguments = $"-s {UDPServerHostName} -p {UDPServer.Port} -k \"{UDPServer.Password}\" -m {UDPServer.EncryptMethod} -t 120";

                            if (!string.IsNullOrEmpty(UDPServer.Protocol))
                            {
                                UDPServerInstance.StartInfo.Arguments += $" -O {UDPServer.Protocol}";

                                if (!string.IsNullOrEmpty(UDPServer.ProtocolParam))
                                {
                                    UDPServerInstance.StartInfo.Arguments += $" -G \"{UDPServer.ProtocolParam}\"";
                                }
                            }

                            if (!string.IsNullOrEmpty(UDPServer.OBFS))
                            {
                                UDPServerInstance.StartInfo.Arguments += $" -o {UDPServer.OBFS}";

                                if (!string.IsNullOrEmpty(UDPServer.OBFSParam))
                                {
                                    UDPServerInstance.StartInfo.Arguments += $" -g \"{UDPServer.OBFSParam}\"";
                                }
                            }

                            UDPServerInstance.StartInfo.Arguments += $" -b {Global.Settings.LocalAddress} -l {Global.Settings.Socks5LocalPort + 1} -u";
                        }


                        if (UDPServer.Type == "TR")
                        {
                            File.WriteAllText("data\\UDPServerlast.json", Newtonsoft.Json.JsonConvert.SerializeObject(new Models.Trojan()
                            {
                                local_addr = Global.Settings.LocalAddress,
                                local_port = Global.Settings.Socks5LocalPort + 1,
                                remote_addr = UDPServerHostName,
                                remote_port = UDPServer.Port,
                                password = new List<string>()
                                {
                                    UDPServer.Password
                                }
                            }));

                            UDPServerInstance = GetProcess("bin\\Trojan.exe");
                            UDPServerInstance.StartInfo.Arguments = "-c ..\\data\\UDPServerlast.json";
                        }

                        Utils.Logging.Info($"UDPServer : {UDPServerInstance.StartInfo.Arguments}");
                        File.Delete("logging\\UDPServer.log");
                        UDPServerInstance.OutputDataReceived += (sender, e) =>
                        {
                            try
                            {
                                File.AppendAllText("logging\\UDPServer.log", string.Format("{0}\r\n", e.Data));
                            }
                            catch (Exception)
                            {
                            }
                        };
                        UDPServerInstance.ErrorDataReceived += (sender, e) =>
                        {
                            try
                            {
                                File.AppendAllText("logging\\UDPServer.log", string.Format("{0}\r\n", e.Data));
                            }
                            catch (Exception)
                            {
                            }
                        };

                        UDPServerInstance.Start();
                        UDPServerInstance.BeginOutputReadLine();
                        UDPServerInstance.BeginErrorReadLine();


                        fallback += $" -rudp 127.0.0.1:{Global.Settings.Socks5LocalPort + 1}";
                    }
                    else
                    {
                        fallback += $" -rudp {UDPServerHostName}:{UDPServer.Port}";
                    }
                }
            }
            else
            {
                fallback += $" -rudp 127.0.0.1:{Global.Settings.Socks5LocalPort}";
            }

            return true;
        }
    }
}