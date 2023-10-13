package oomparser

import (
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/euank/go-kmsg-parser/kmsgparser"
	"k8s.io/klog"
)

var (
	legacyContainerRegexp = regexp.MustCompile(`Task in (.*) killed as a result of limit of (.*)`)
	firstLineRegexp       = regexp.MustCompile(`invoked oom-killer:`)
	containerRegexp       = regexp.MustCompile(`oom-kill:constraint=(.*),nodemask=(.*),cpuset=(.*),mems_allowed=(.*),oom_memcg=(.*),task_memcg=(.*),task=(.*),pid=(.*),uid=(.*)`)
	lastLineRegexp        = regexp.MustCompile(`Killed process ([0-9]+) \((.+)\)`)
	legacyLastLineRegexp  = regexp.MustCompile(`oom_reaper: reaped process ([0-9]+) \((.+)\)`)
)

type OomParser struct {
	parser kmsgparser.Parser
}

type OomInstance struct {
	// process id of the killed process
	Pid int
	// the name of the killed process
	ProcessName string
	// the time that the process was reported to be killed,
	// accurate to the minute
	TimeOfDeath time.Time
	// the absolute name of the container that OOMed
	ContainerName string
	// the absolute name of the container that was killed
	// due to the OOM.
	VictimContainerName string
	// the constraint that triggered the OOM.  One of CONSTRAINT_NONE,
	// CONSTRAINT_CPUSET, CONSTRAINT_MEMORY_POLICY, CONSTRAINT_MEMCG
	Constraint string
}

func New() (*OomParser, error) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		return nil, err
	}
	return &OomParser{parser}, nil
}

func (p *OomParser) StreamOoms(outStream chan<- *OomInstance) {
	kmsgEntries := p.parser.Parse()
	defer p.parser.Close()

	for msg := range kmsgEntries {
		if checkIfStartOfOomMessages(msg.Message) {
			oomCurrentInstance := &OomInstance{
				ContainerName:       "/",
				VictimContainerName: "/",
				TimeOfDeath:         msg.Timestamp,
			}
			for kmsg := range kmsgEntries {
				finished, err := getContainerName(kmsg.Message, oomCurrentInstance)
				if err != nil {
					klog.Errorf("%v", err)
				}
				if !finished {
					finished, err = getProcessNamePid(kmsg.Message, oomCurrentInstance)
					if err != nil {
						klog.Errorf("%v", err)
					}
				}
				klog.Infof("check for finished kmsg, msg: %s, finished: %v", kmsg.Message, finished)
				if finished {
					oomCurrentInstance.TimeOfDeath = kmsg.Timestamp
					break
				}
			}
			outStream <- oomCurrentInstance
		}
	}
}

// gets the container name from a line and adds it to the oomInstance.
func getContainerName(line string, currentOomInstance *OomInstance) (bool, error) {
	parsedLine := containerRegexp.FindStringSubmatch(line)
	if parsedLine == nil {
		// Fall back to the legacy format if it isn't found here.
		return false, getLegacyContainerName(line, currentOomInstance)
	}
	currentOomInstance.ContainerName = parsedLine[6]
	currentOomInstance.VictimContainerName = parsedLine[5]
	currentOomInstance.Constraint = parsedLine[1]
	pid, err := strconv.Atoi(parsedLine[8])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = parsedLine[7]
	return true, nil
}

// gets the pid, name, and date from a line and adds it to oomInstance
func getProcessNamePid(line string, currentOomInstance *OomInstance) (bool, error) {
	reList := lastLineRegexp.FindStringSubmatch(line)

	if reList == nil {
		return getLegacyProcessNamePid(line, currentOomInstance)
	}

	pid, err := strconv.Atoi(reList[1])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = reList[2]
	return true, nil
}

func getLegacyProcessNamePid(line string, currentOomInstance *OomInstance) (bool, error) {
	reList := legacyLastLineRegexp.FindStringSubmatch(line)

	if reList == nil {
		return false, nil
	}

	pid, err := strconv.Atoi(reList[1])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = reList[2]
	return true, nil
}

// gets the container name from a line and adds it to the oomInstance.
func getLegacyContainerName(line string, currentOomInstance *OomInstance) error {
	parsedLine := legacyContainerRegexp.FindStringSubmatch(line)
	if parsedLine == nil {
		return nil
	}
	currentOomInstance.ContainerName = path.Join("/", parsedLine[1])
	currentOomInstance.VictimContainerName = path.Join("/", parsedLine[2])
	return nil
}

// uses regex to see if line is the start of a kernel oom log
func checkIfStartOfOomMessages(line string) bool {
	potentialOomStart := firstLineRegexp.MatchString(line)
	return potentialOomStart
}
