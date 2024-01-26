package cmd

import (
	"fmt"
	"github.com/fatih/color"
	console "github.com/longyuan/domain.v3/console"
	"github.com/spf13/cobra"
	"os"
	"strconv"
)

func Cmd() []*cobra.Command {
	var sslCmd = &cobra.Command{
		Use:     "ssl",
		Short:   "Host SSL Info",
		Example: "ssl www.baidu.com",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) <= 0 {
				return
			}
			err := console.SSL(args[0])
			if err != nil {
				color.Red(fmt.Sprint(err))
				return
			}
		},
	}

	var whoisCmd = &cobra.Command{
		Use:     "whois",
		Short:   "Host Whois Info",
		Example: "whois gitlab.com",
		Run: func(cmd *cobra.Command, args []string) {
			original, err := cmd.Flags().GetString("original")
			if err != nil {
				color.Red(fmt.Sprint(err))
				return
			}
			if len(args) <= 0 {
				return
			}
			err = console.Whois(args[0], original != "false")
			if err != nil {
				color.Red(fmt.Sprint(err))
				return
			}
		},
	}
	whoisCmd.Flags().StringP("original", "o", "false", "original information")

	var scanCmd = &cobra.Command{
		Use:     "scan",
		Short:   "Scan Config",
		Example: "scan ./domain.txt",
		Run: func(cmd *cobra.Command, args []string) {
			jsonFormat, err := cmd.Flags().GetBool("json")
			if err != nil {
				color.Red(fmt.Sprint(err))
				os.Exit(1)
				return
			}
			deadlineString, err := cmd.Flags().GetString("deadline")
			if err != nil {
				color.Red(fmt.Sprint(err))
				os.Exit(1)
				return
			}
			deadline, err := strconv.Atoi(deadlineString)
			if err != nil {
				color.Red(fmt.Sprint(err))
				os.Exit(1)
				return
			}
			if len(args) <= 0 {
				os.Exit(1)
				return
			}
			err = console.Scan(args[0], deadline, jsonFormat)
			if err != nil {
				color.Red(fmt.Sprint(err))
				os.Exit(1)
				return
			}
		},
	}
	scanCmd.Flags().Bool("json", false, "JSON formatting")
	scanCmd.Flags().StringP("deadline", "d", "30", "original information")

	return []*cobra.Command{
		sslCmd,
		whoisCmd,
		scanCmd,
	}
}
