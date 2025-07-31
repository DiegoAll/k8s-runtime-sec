package cmd

import (
	"fmt"
	"log"

	"k8s-bad-cli/behaviors"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Inicializa la aplicación",
	Long:  `Inicializa la aplicación con las configuraciones proporcionadas.`,
	Run: func(cmd *cobra.Command, args []string) {
		vector, err := cmd.Flags().GetString("vector")
		if err != nil {
			log.Fatalf("Error al obtener el vector: %v", err)
		}

		interactive, err := cmd.Flags().GetBool("interactive")
		if err != nil {
			log.Fatalf("Error al obtener la bandera interactiva: %v", err)
		}

		if interactive {
			behaviors.ShowMenu()
		} else {
			switch vector {
			case "A":
				behaviors.RunVectorA()
			case "B":
				behaviors.RunVectorB()
			default:
				fmt.Println("Por favor, especifica un vector válido: A o B, o usa --interactive")
			}
		}
	},
}

func init() {
	initCmd.Flags().String("vector", "", "Vector type (A or B)")
	initCmd.Flags().Bool("interactive", false, "Modo interactivo")
}
