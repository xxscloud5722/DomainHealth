package console

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/longyuan/domain.v3/client"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

func Whois(host string, original bool) error {
	domain, err := client.ParseDomain(host)
	if err != nil {
		return err
	}
	context, err := client.Whois(*domain)
	if err != nil {
		return err
	}
	if original {
		color.White(strings.Join(context, "\n"))
	} else {
		whoisInfo, err := client.ParseWhoisInfo(context)
		if err != nil {
			return err
		}
		whoisInfo.Println()
	}
	return nil
}

func SSL(host string) error {
	cert, err := client.SSL(host)
	if err != nil {
		return err
	}
	cert.Print()
	return nil
}

type DomainScan struct {
	domain    string
	message   string
	sslBefore time.Time
	sslAfter  time.Time

	whoisCreationDate       time.Time
	whoisUpdatedDate        time.Time
	whoisRegistryExpiryDate time.Time
}

func (domain *DomainScan) sslDays() float64 {
	sslDuration := domain.sslAfter.Sub(time.Now())
	return sslDuration.Hours() / 24
}

func (domain *DomainScan) whoisDays() float64 {
	whoisDuration := domain.whoisRegistryExpiryDate.Sub(time.Now())
	return whoisDuration.Hours() / 24
}

func (domain *DomainScan) sslDaysContext() string {
	sslDays := domain.sslDays()
	if sslDays <= -106751 {
		return "查询失败: " + domain.message
	} else if sslDays < 0 {
		return "已过期: " + strconv.Itoa(int(math.Abs(sslDays))) + "天"
	} else if sslDays < 15 {
		return "即将过期: " + strconv.Itoa(int(math.Abs(sslDays))) + "天"
	} else {
		return "剩余: " + strconv.Itoa(int(math.Abs(sslDays))) + "天"
	}
}

func (domain *DomainScan) whoisDaysContext() string {
	whoisDays := domain.whoisDays()
	if whoisDays <= -106751 {
		return "查询失败: " + domain.message
	} else if whoisDays < 0 {
		return "已过期: " + strconv.Itoa(int(math.Abs(whoisDays))) + "天"
	} else if whoisDays < 15 {
		return "即将过期: " + strconv.Itoa(int(math.Abs(whoisDays))) + "天"
	} else {
		return "剩余: " + strconv.Itoa(int(math.Abs(whoisDays))) + "天"
	}
}

func Scan(path string, deadline int, jsonFormat bool) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rows = strings.Split(strings.ReplaceAll(string(file), "\r\n", "\n"), "\n")
	if !jsonFormat {
		color.Green("Scan Domain ....")
	}
	var domain = client.Analysis(client.ParseDomains(rows))
	if err != nil {
		return err
	}
	if jsonFormat {
		var domainErrorCount = 0
		var domainWarnCount = 0
		var domainSuccessCount = 0
		var domainMap []map[string]string
		for index, item := range domain {
			domainItem := make(map[string]string)
			if item.Message != nil {
				domainItem["Index"] = strconv.Itoa(index + 1)
				domainItem["Name"] = item.Name
				domainItem["CreateTime"] = ""
				domainItem["ExpiryTime"] = ""
				domainItem["AvailableDays"] = ""
				domainItem["Message"] = *item.Message
				domainErrorCount++
			} else {
				day, _, _ := item.Whois.RegistryExpiryDateParse()
				domainItem["Index"] = strconv.Itoa(index + 1)
				domainItem["Name"] = item.Name
				domainItem["CreateTime"] = item.Whois.CreationDate.Format("2006-01-02")
				domainItem["ExpiryTime"] = item.Whois.RegistryExpiryDate.Format("2006-01-02")
				domainItem["AvailableDays"] = strconv.Itoa(day)
				domainItem["Message"] = ""
				if day <= deadline {
					domainWarnCount++
				} else {
					domainSuccessCount++
				}
			}
			domainMap = append(domainMap, domainItem)
		}

		var errorCount = 0
		var warnCount = 0
		var successCount = 0
		var sslMap []map[string]string
		var sslIndex = 0
		for _, item := range domain {
			for _, child := range *item.Child {
				sslItem := make(map[string]string)
				if child.Message != nil {
					sslItem["Index"] = strconv.Itoa(sslIndex + 1)
					sslItem["Name"] = child.Name
					sslItem["CreateTime"] = ""
					sslItem["ExpiryTime"] = ""
					sslItem["AvailableDays"] = ""
					sslItem["Message"] = *child.Message
					errorCount++
				} else {
					day, _, _ := child.SSL.NotAfterDateParse()
					sslItem["Index"] = strconv.Itoa(sslIndex + 1)
					sslItem["Name"] = child.Name
					sslItem["CreateTime"] = child.SSL.NotBefore.Format("2006-01-02")
					sslItem["ExpiryTime"] = child.SSL.NotAfter.Format("2006-01-02")
					sslItem["AvailableDays"] = strconv.Itoa(day)
					sslItem["Message"] = ""
					if day <= deadline {
						warnCount++
					} else {
						successCount++
					}
				}
				sslMap = append(sslMap, sslItem)
				sslIndex += 1
			}
		}

		result := make(map[string]any)
		result["SSL"] = sslMap
		result["Domain"] = domainMap

		result["DomainTotal"] = len(domain)
		result["DomainError"] = domainErrorCount
		result["DomainWarn"] = domainWarnCount
		result["DomainSuccess"] = domainSuccessCount

		result["SSLTotal"] = len(sslMap)
		result["SSLError"] = errorCount
		result["SSLWarn"] = warnCount
		result["SSLSuccess"] = successCount
		var jsonData []byte
		jsonData, err = json.Marshal(result)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonData))
	} else {
		var table [][]string
		for index, item := range domain {
			if item.Message != nil {
				table = append(table, []string{
					strconv.Itoa(index + 1), item.Name,
					"",
					"",
					"0", *item.Message,
				})
			} else {
				day, _, _ := item.Whois.RegistryExpiryDateParse()
				table = append(table, []string{
					strconv.Itoa(index + 1), item.Name,
					item.Whois.CreationDate.Format("2006-01-02"),
					item.Whois.RegistryExpiryDate.Format("2006-01-02"),
					strconv.Itoa(day), "",
				})
			}
		}
		PrintTable([]string{"序号", "域名", "Whois 创建日期", "Whois 过期日期", "Whois 剩余天数", "错误消息"}, table)

		table = [][]string{}
		var sslIndex = 0
		for _, item := range domain {
			for _, child := range *item.Child {
				if child.Message != nil {
					table = append(table, []string{
						strconv.Itoa(sslIndex + 1), child.Name,
						"", "", "0", *child.Message,
					})
				} else {
					day, _, _ := child.SSL.NotAfterDateParse()
					table = append(table, []string{
						strconv.Itoa(sslIndex + 1), child.Name,
						child.SSL.NotBefore.Format("2006-01-02"),
						child.SSL.NotAfter.Format("2006-01-02"),
						strconv.Itoa(day), "",
					})
				}
				sslIndex += 1
			}
		}
		PrintTable([]string{"序号", "域名", "SSL 创建日期", "SSL 过期日期", "SSL 剩余天数", "错误消息"}, table)
	}
	return nil
}

func DomainTemplateCPWeChat(value string) string {
	if strings.Index(value, "查询失败") > -1 {
		return "> <font color=\"red\">" + value + "</font>\n"
	}
	if strings.Index(value, "已过期") > -1 {
		return "> <font color=\"red\">" + value + "</font>\n"
	}
	if strings.Index(value, "即将过期") > -1 {
		return "> <font color=\"warning\">" + value + "</font>\n"
	}
	return "> " + value + "\n"
}
