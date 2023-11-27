package cmd

import (
	"fmt"
	"github.com/fatih/color"
	console "github.com/longyuan/domain.v3/console"
	"github.com/spf13/cobra"
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
			if len(args) <= 0 {
				return
			}
			err := console.Scan(args[0])
			if err != nil {
				color.Red(fmt.Sprint(err))
				return
			}
		},
	}

	return []*cobra.Command{
		sslCmd,
		whoisCmd,
		scanCmd,
	}
}
