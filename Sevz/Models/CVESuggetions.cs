using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using MySql.Data.MySqlClient;
using System.Data;

namespace Sevz.Models
{
    public static class AttackSuggestionService
    {
        // 서버 소프트웨어와 버전에 따른 맞춤형 공격을 제안하는 메서드
        public static List<string> SuggestAttacksForVersion(string software, string version)
        {
            List<string> suggestions = new List<string>();

            // software 변수를 소문자로 변환
            software = software.ToLower();

            // cve-db 연결
            // MySQL 연결 문자열
            string connectionString = "Server=223.130.157.192; Database=sevztool; User ID=sevz; Password=sevzsevz;";

            // MySQL 연결 객체 생성
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                try
                {
                    // 연결 열기
                    connection.Open();

                    // SQL 쿼리 작성
                    string query = "SELECT cve, level, exp FROM cve WHERE product = @software AND ver LIKE @version";

                    // MySqlCommand 객체 생성
                    using (MySqlCommand command = new MySqlCommand(query, connection))
                    {
                        // 쿼리 매개변수 설정
                        command.Parameters.AddWithValue("@software", software);
                        command.Parameters.AddWithValue("@version", "%" + version + "%"); // version이 포함된 레코드 찾기 위해 LIKE 사용

                        // 쿼리 실행 및 결과 읽기
                        using (MySqlDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                // 예를 들어, CVE 정보 (cve, level, exp)를 가져와서 suggestion 리스트에 추가
                                string cve = reader.GetString("cve");
                                string level = reader.GetString("level");
                                string exp = reader.GetString("exp");

                                // CVE 번호와 레벨 및 설명? 추가
                                // suggestions.Add($"CVE: {cve}, Level: {level}, Explanation: {exp}");
                                suggestions.Add($"CVE: {cve}{Environment.NewLine}Level: {level}{Environment.NewLine}Explanation: {exp}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }


            // Apache 버전별 맞춤형 공격 제안
            if (software == "apache")
            {
                suggestions.Add("CVE-2021-40438: Apache 2.4.41에서 SSRF(서버사이드 요청 위조) 취약점을 이용하세요.");
                suggestions.Add("Metasploit 모듈: exploit/multi/http/apache_optionsbleed");

                suggestions.Add("CVE-2019-0211: Apache 2.4.29에서 권한 상승 취약점을 이용하세요.");
                suggestions.Add("Metasploit 모듈: exploit/multi/http/apache_mod_cgi_bash_env_exec");


                suggestions.Add("CVE-2017-9798: Apache 2.2.34에서 Out of Bound Write 취약점을 이용하세요.");
                suggestions.Add("Metasploit 모듈: exploit/multi/http/apache_range_dos");

                // 추가 Apache 버전별 취약점 및 공격 기법 제안 가능
            }

            // Nginx 버전별 맞춤형 공격 제안
            if (software == "nginx")
            {
                if (version == "1.18.0")
                {
                    suggestions.Add("CVE-2021-23017: Nginx 1.18.0에서 메모리 손상 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/nginx_chunked_size");
                }
                else if (version == "1.14.0")
                {
                    suggestions.Add("CVE-2018-16843: Nginx 1.14.0에서 HTTP/2 스택 오버플로우 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/linux/http/nginx_http2_stack_buffer_overflow");
                }
                // 추가 Nginx 버전별 취약점 및 공격 기법 제안 가능
            }

            // Microsoft IIS 버전별 맞춤형 공격 제안
            if (software == "iis")
            {
                if (version == "7.5")
                {
                    suggestions.Add("CVE-2017-7269: IIS 7.5에서 WebDAV RCE(원격 코드 실행) 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/windows/iis/iis_webdav_scstoragepathfromurl");
                }
                else if (version == "10.0")
                {
                    suggestions.Add("CVE-2021-31166: IIS 10.0에서 HTTP.sys 원격 코드 실행 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/windows/http/iis_http_sys_rce");
                }
            }

            // WordPress 버전별 맞춤형 공격 제안
            if (software == "wordpress")
            {
                if (version == "5.7")
                {
                    suggestions.Add("CVE-2021-29447: WordPress 5.7에서 XML 파싱의 XSS 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/wp_slideshowgallery_upload");
                }
                else if (version == "5.6")
                {
                    suggestions.Add("CVE-2020-36287: WordPress 5.6에서 데이터베이스 관련 SQL Injection 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/unix/webapp/wp_wysija_newsletters");
                }
                else if (version == "4.7.0")
                {
                    suggestions.Add("CVE-2017-5487: WordPress 4.7.0에서 REST API 인증 우회 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/wp_restapi_auth_bypass");
                }
                // 추가 WordPress 버전별 취약점 및 공격 기법 제안 가능
            }

            // Drupal 버전별 맞춤형 공격 제안
            if (software == "drupal")
            {
                if (version == "7.x")
                {
                    suggestions.Add("CVE-2014-3704: Drupal 7.x에서 SQL Injection 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/drupal_drupageddon");
                }
                else if (version == "8.6.x")
                {
                    suggestions.Add("CVE-2019-6340: Drupal 8.6.x에서 원격 코드 실행 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/drupal_drupalgeddon2");
                }
                // 추가 Drupal 버전별 취약점 및 공격 기법 제안 가능
            }

            // 추가 소프트웨어와 버전별 취약점 및 공격 기법 제안 가능
            if (software == "Joomla")
            {
                if (version == "3.4.5")
                {
                    suggestions.Add("CVE-2015-8562: Joomla 3.4.5에서 PHP Object Injection 취약점을 이용하세요.");
                    suggestions.Add("Metasploit 모듈: exploit/multi/http/joomla_http_header_rce");
                }
            }

            return suggestions;
        }
    }
}
