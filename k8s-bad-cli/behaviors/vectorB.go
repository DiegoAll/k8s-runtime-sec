package behaviors

import (
	"fmt"
	"time"
)

// Puede ser algo externo con LaunchIngressRemoteFileCopyToolsInContainer()  SERIA REPETIDO

func RunVectorB() {
	fmt.Println("Ejecutando la función para vector B")

	LaunchSuspiciousNetworkToolInContainer()
	time.Sleep(3 * time.Second)

	DirectoryTraversalMonitoredFileRead() //funciona
	time.Sleep(3 * time.Second)

	// Descarga de archivo con curl -o (No parece ser necesaria)
	//LaunchIngressRemoteFileCopyToolsInContainer()
	// time.Sleep(3 * time.Second)

	PolkitLocalPrivilegeEscalationVulnerability_CVE_2021_4034()
	time.Sleep(3 * time.Second)

	//CVE-2021-3156 (Baron samedit) - The vulnerability does not exist, therefore, it is a failed scenario.
	// SudoPotentialPrivilegeEscalation()
	// time.Sleep(3 * time.Second)

	MountLaunchedInPrivilegedContainer()

	SudoPotentialPrivilegeEscalationExploitation()
	time.Sleep(3 * time.Second)

	// Also trigger Read sensitive file unstrusted

	// Release agent container escape
	DetecteReleaseAgentFileContainerEscapes() // requiere privilegios
	time.Sleep(3 * time.Second)

}
