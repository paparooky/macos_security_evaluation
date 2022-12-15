#!/bin/zsh

##  This script will attempt to audit all of the settings based on the installed profile.

##  This script is provided as-is and should be fully tested on a system that is not in a production environment.

###################  Variables  ###################

pwpolicy_file="/var/tmp/pwpolicy.xml"

###################  COMMANDS START BELOW THIS LINE  ###################

## Must be run as root
if [[ $EUID -ne 0 ]]; then
    /bin/echo "This script must be run as root"
    exit 1
fi

# path to PlistBuddy
plb="/usr/libexec/PlistBuddy"

# get the currently logged in user
CURRENT_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURR_USER_UID=$(/usr/bin/id -u $CURRENT_USER)

# get system architecture
arch=$(/usr/bin/arch)

# configure colors for text
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'

audit_plist="/Library/Preferences/org.cisv8.audit.plist"
audit_log="/Library/Logs/cisv8_baseline.log"

# pause function
pause(){
vared -p "Press [Enter] key to continue..." -c fackEnterKey
}

ask() {
    # if fix flag is passed, assume YES for everything
    if [[ $fix ]]; then
        return 0
    fi

    while true; do

        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question - use /dev/tty in case stdin is redirected from somewhere else
        printf "${YELLOW} $1 [$prompt] ${STD}"
        read REPLY

        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac

    done
}

# function to display menus
show_menus() {
    lastComplianceScan=$(defaults read /Library/Preferences/org.cisv8.audit.plist lastComplianceCheck)

    if [[ $lastComplianceScan == "" ]];then
        lastComplianceScan="No scans have been run"
    fi

    /usr/bin/clear
    /bin/echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    /bin/echo "        M A I N - M E N U"
    /bin/echo "  macOS Security Compliance Tool"
    /bin/echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    /bin/echo "Last compliance scan: $lastComplianceScan
"
    /bin/echo "1. View Last Compliance Report"
    /bin/echo "2. Run New Compliance Scan"
    /bin/echo "3. Run Commands to remediate non-compliant settings"
    /bin/echo "4. Exit"
}

# function to read options
read_options(){
    local choice
    vared -p "Enter choice [ 1 - 4 ] " -c choice
    case $choice in
        1) view_report ;;
        2) run_scan ;;
        3) run_fix ;;
        4) exit 0;;
        *) echo -e "${RED}Error: please choose an option 1-4...${STD}" && sleep 1
    esac
}

# function to reset and remove plist file.  Used to clear out any previous findings
reset_plist(){
    echo "Clearing results from /Library/Preferences/org.cisv8.audit.plist"
    defaults delete /Library/Preferences/org.cisv8.audit.plist
}

# Generate the Compliant and Non-Compliant counts. Returns: Array (Compliant, Non-Compliant)
compliance_count(){
    compliant=0
    non_compliant=0

    results=$(/usr/libexec/PlistBuddy -c "Print" /Library/Preferences/org.cisv8.audit.plist)

    while IFS= read -r line; do
        if [[ "$line" =~ "finding = false" ]]; then
            compliant=$((compliant+1))
        fi
        if [[ "$line" =~ "finding = true" ]]; then
            non_compliant=$((non_compliant+1))
        fi
    done <<< "$results"

    # Enable output of just the compliant or non-compliant numbers.
    if [[ $1 = "compliant" ]]
    then
        /bin/echo $compliant
    elif [[ $1 = "non-compliant" ]]
    then
        /bin/echo $non_compliant
    else # no matching args output the array
        array=($compliant $non_compliant)
        /bin/echo ${array[@]}
    fi
}

exempt_count(){
    exempt=0

    if [[ -e "/Library/Managed Preferences/org.cisv8.audit.plist" ]];then
        mscp_prefs="/Library/Managed Preferences/org.cisv8.audit.plist"
    else
        mscp_prefs="/Library/Preferences/org.cisv8.audit.plist"
    fi

    results=$(/usr/libexec/PlistBuddy -c "Print" "$mscp_prefs")

    while IFS= read -r line; do
        if [[ "$line" =~ "exempt = true" ]]; then
            exempt=$((exempt+1))
        fi
    done <<< "$results"

    /bin/echo $exempt
}


generate_report(){
    count=($(compliance_count))
    exempt_rules=$(exempt_count)
    compliant=${count[1]}
    non_compliant=${count[2]}

    total=$((non_compliant + compliant - exempt_rules))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    /bin/echo
    echo "Number of tests passed: ${GREEN}$compliant${STD}"
    echo "Number of test FAILED: ${RED}$non_compliant${STD}"
    echo "Number of exempt rules: ${YELLOW}$exempt_rules${STD}"
    echo "You are ${YELLOW}$percentage%${STD} percent compliant!"
    pause
}

view_report(){

    if [[ $lastComplianceScan == "No scans have been run" ]];then
        /bin/echo "no report to run, please run new scan"
        pause
    else
        generate_report
    fi
}

# Designed for use with MDM - single unformatted output of the Compliance Report
generate_stats(){
    count=($(compliance_count))
    compliant=${count[1]}
    non_compliant=${count[2]}

    total=$((non_compliant + compliant))
    percentage=$(printf %.2f $(( compliant * 100. / total )) )
    /bin/echo "PASSED: $compliant FAILED: $non_compliant, $percentage percent compliant!"
}

run_scan(){
# append to existing logfile
if [[ $(/usr/bin/tail -n 1 "$audit_log" 2>/dev/null) = *"Remediation complete" ]]; then
 	/bin/echo "$(date -u) Beginning cisv8 baseline scan" >> "$audit_log"
else
 	/bin/echo "$(date -u) Beginning cisv8 baseline scan" > "$audit_log"
fi

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID

# write timestamp of last compliance check
/usr/bin/defaults write "$audit_plist" lastComplianceCheck "$(date)"
    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_auditd_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_auditd_enabled passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_auditd_enabled passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_auditd_enabled failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_auditd_enabled failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_auditd_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_auditd_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_auditd_enabled does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_auditd_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_aa_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_aa_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_aa_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_aa_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_aa_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_aa_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_aa_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_aa_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_ad_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ad_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ad_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_ad_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_ad_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_ad_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_ad_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_ad_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_ex_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_ex_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ex_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ex_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_ex_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_ex_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_ex_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_ex_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_ex_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_ex_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_ex_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_ex_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fd_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fd_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fd_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_fd_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_fd_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fd_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_fd_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fd_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fm_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fm'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fm_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fm_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_fm_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_fm_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fm_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_fm_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fm_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fr_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fr_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fr_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_fr_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_fr_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fr_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_fr_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fr_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_fw_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fw_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fw_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_fw_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_fw_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_fw_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_fw_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_fw_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_flags_lo_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_lo_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_lo_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) audit_flags_lo_configure passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_flags_lo_configure passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_flags_lo_configure failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_flags_lo_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_flags_lo_configure -dict-add finding -bool NO
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: audit_retention_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control
)
    # expected result {'string': '7d'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_retention_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_retention_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "7d" ]]; then
        /bin/echo "$(date -u) audit_retention_configure passed (Result: $result_value, Expected: "{'string': '7d'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - audit_retention_configure passed (Result: $result_value, Expected: "{'string': '7d'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) audit_retention_configure failed (Result: $result_value, Expected: "{'string': '7d'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_retention_configure failed (Result: $result_value, Expected: "{'string': '7d'}")"
        else
            /bin/echo "$(date -u) audit_retention_configure failed (Result: $result_value, Expected: "{'string': '7d'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - audit_retention_configure failed (Result: $result_value, Expected: "{'string': '7d'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) audit_retention_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" audit_retention_configure -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_addressbook_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_addressbook_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_addressbook_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_addressbook_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_addressbook_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_addressbook_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_addressbook_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_addressbook_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_addressbook_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_appleid_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_appleid_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath 'string(//*[contains(text(), "DisabledPreferencePanes")]/following-sibling::*[1])' - | /usr/bin/grep -c com.apple.preferences.AppleIDPrefPane
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_appleid_prefpane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_appleid_prefpane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) icloud_appleid_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_appleid_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_appleid_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_appleid_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) icloud_appleid_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_appleid_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_appleid_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_appleid_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_bookmarks_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_bookmarks_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_bookmarks_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_bookmarks_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_bookmarks_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_bookmarks_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_bookmarks_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_bookmarks_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_bookmarks_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_calendar_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_calendar_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudCalendar = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_calendar_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_calendar_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) icloud_calendar_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_calendar_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_calendar_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_calendar_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) icloud_calendar_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_calendar_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_calendar_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_calendar_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_drive_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_drive_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_drive_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_drive_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_drive_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_drive_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_drive_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_drive_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_drive_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_keychain_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_keychain_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_keychain_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_keychain_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_keychain_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_keychain_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_keychain_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_keychain_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_keychain_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_mail_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_mail_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_mail_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_mail_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_mail_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_mail_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_mail_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_mail_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_mail_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_notes_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_notes_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_notes_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_notes_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_notes_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_notes_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_notes_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_notes_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_notes_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_photos_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_photos_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_photos_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_photos_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_photos_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_photos_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_photos_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_photos_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_photos_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_reminders_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_reminders_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_reminders_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_reminders_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_reminders_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_reminders_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_reminders_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_reminders_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_reminders_disable -dict-add finding -bool NO
fi
    
#####----- Rule: icloud_sync_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20, AC-20(1)
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: icloud_sync_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDesktopAndDocuments').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_sync_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('icloud_sync_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) icloud_sync_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - icloud_sync_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) icloud_sync_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_sync_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) icloud_sync_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - icloud_sync_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) icloud_sync_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" icloud_sync_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_airdrop_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_airdrop_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_airdrop_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_airdrop_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_airdrop_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_airdrop_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_airdrop_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_airdrop_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_airdrop_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_apple_mobile_file_integrity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-3
# * SI-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_apple_mobile_file_integrity_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1"
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_apple_mobile_file_integrity_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_apple_mobile_file_integrity_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) os_apple_mobile_file_integrity_enforce passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_apple_mobile_file_integrity_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_apple_mobile_file_integrity_enforce passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_apple_mobile_file_integrity_enforce failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_apple_mobile_file_integrity_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_apple_mobile_file_integrity_enforce failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            /bin/echo "$(date -u) os_apple_mobile_file_integrity_enforce failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_apple_mobile_file_integrity_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_apple_mobile_file_integrity_enforce failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_apple_mobile_file_integrity_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_apple_mobile_file_integrity_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_appleid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_appleid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipCloudSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_appleid_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_appleid_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_appleid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_appleid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_appleid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_appleid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_appleid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_bonjour_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_bonjour_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_bonjour_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_bonjour_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_bonjour_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_bonjour_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_bonjour_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_bonjour_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_bonjour_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_calendar_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_calendar_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c "/Applications/Calendar.app"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_calendar_app_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_calendar_app_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_calendar_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_calendar_app_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_calendar_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_calendar_app_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_calendar_app_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_calendar_app_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_calendar_app_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_calendar_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_config_data_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2(5)
# * SI-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_config_data_install_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_config_data_install_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_config_data_install_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_config_data_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_config_data_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_config_data_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_config_data_install_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_config_data_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: os_directory_services_configured -----#####
## Addresses the following NIST 800-53 controls: 
# * N/A
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_directory_services_configured ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/dscl localhost -list . | /usr/bin/grep -vE '(Contact|Search|Local|^$)'; /bin/echo $?
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_directory_services_configured'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_directory_services_configured'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) os_directory_services_configured passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_directory_services_configured passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            /bin/echo "$(date -u) os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_directory_services_configured failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_directory_services_configured does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_directory_services_configured -dict-add finding -bool NO
fi
    
#####----- Rule: os_facetime_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_facetime_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/FaceTime.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_facetime_app_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_facetime_app_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_facetime_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_facetime_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_facetime_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_facetime_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_facetime_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_facetime_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_facetime_app_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_facetime_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_firewall_log_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12
# * SC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_firewall_log_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep -c "Log mode is on"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_firewall_log_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_firewall_log_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_firewall_log_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_firewall_log_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_firewall_log_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_firewall_log_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_firewall_log_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_firewall_log_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_firewall_log_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_firewall_log_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_gatekeeper_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_gatekeeper_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_gatekeeper_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_gatekeeper_rearm -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_gatekeeper_rearm ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security')\
.objectForKey('GKAutoRearm').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_rearm'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_rearm'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_gatekeeper_rearm passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_rearm passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_gatekeeper_rearm failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_rearm failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_gatekeeper_rearm failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_gatekeeper_rearm failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_gatekeeper_rearm does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_gatekeeper_rearm -dict-add finding -bool NO
fi
    
#####----- Rule: os_handoff_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_handoff_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_handoff_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_handoff_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_handoff_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_handoff_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_handoff_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_handoff_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_handoff_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_httpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_httpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_httpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_httpd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_httpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_icloud_storage_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_icloud_storage_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipiCloudStorageSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_icloud_storage_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_icloud_storage_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_icloud_storage_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_icloud_storage_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_icloud_storage_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_icloud_storage_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_icloud_storage_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_internet_accounts_prefpane_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7(5)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_internet_accounts_prefpane_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath 'string(//*[contains(text(), "DisabledPreferencePanes")]/following-sibling::*[1])' - | /usr/bin/grep -c com.apple.preferences.internetaccounts
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_internet_accounts_prefpane_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_internet_accounts_prefpane_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_internet_accounts_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_internet_accounts_prefpane_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_internet_accounts_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_internet_accounts_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_internet_accounts_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_internet_accounts_prefpane_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_internet_accounts_prefpane_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_internet_accounts_prefpane_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_ir_support_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_ir_support_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.driver.AppleIRController')\
.objectForKey('DeviceEnabled').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_ir_support_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_ir_support_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_ir_support_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_ir_support_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_ir_support_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_ir_support_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_ir_support_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_ir_support_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_ir_support_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_ir_support_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_mail_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_mail_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/Mail.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_mail_app_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_mail_app_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_mail_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_mail_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_mail_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_mail_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_mail_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_mail_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_mail_app_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_mail_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_mdm_require -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-2
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_mdm_require ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_mdm_require'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_mdm_require'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_mdm_require passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_mdm_require passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_mdm_require failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_mdm_require does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_mdm_require -dict-add finding -bool NO
fi
    
#####----- Rule: os_messages_app_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_messages_app_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/Messages.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_messages_app_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_messages_app_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_messages_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_messages_app_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_messages_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_messages_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_messages_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_messages_app_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_messages_app_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_messages_app_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_nfsd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_nfsd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_nfsd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_nfsd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_nfsd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_parental_controls_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7(2)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_parental_controls_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')\
.objectForKey('familyControlsEnabled').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_parental_controls_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_parental_controls_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_parental_controls_enable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_parental_controls_enable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_parental_controls_enable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_parental_controls_enable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_parental_controls_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_parental_controls_enable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_parental_controls_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_parental_controls_enable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_autofill_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * IA-11
# * IA-5, IA-5(13)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_autofill_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordAutoFill').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_autofill_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_autofill_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_password_autofill_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_password_autofill_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_password_autofill_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_autofill_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_password_autofill_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_autofill_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_password_autofill_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_password_autofill_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_proximity_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_proximity_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_proximity_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_proximity_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_password_proximity_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_password_proximity_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_proximity_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_password_proximity_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_password_proximity_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_password_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_password_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordSharing').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_password_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) os_password_sharing_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_password_sharing_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_password_sharing_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_sharing_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) os_password_sharing_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_password_sharing_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_password_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_password_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_privacy_setup_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_privacy_setup_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipPrivacySetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_privacy_setup_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_privacy_setup_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_privacy_setup_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_privacy_setup_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_privacy_setup_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_privacy_setup_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_privacy_setup_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_siri_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_siri_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSiriSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_siri_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_siri_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_siri_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_siri_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_siri_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_siri_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_siri_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_tftpd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.tftpd" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_tftpd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_tftpd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_tftpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_tftpd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_tftpd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_tftpd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_tftpd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_time_server_enabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl list | /usr/bin/grep -c com.apple.timed
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_time_server_enabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_time_server_enabled'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_time_server_enabled passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_time_server_enabled passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_time_server_enabled failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_time_server_enabled does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_time_server_enabled -dict-add finding -bool NO
fi
    
#####----- Rule: os_touchid_prompt_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-6
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_touchid_prompt_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipTouchIDSetup').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_touchid_prompt_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_touchid_prompt_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) os_touchid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_touchid_prompt_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_touchid_prompt_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_touchid_prompt_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_touchid_prompt_disable -dict-add finding -bool NO
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: os_uucp_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_uucp_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_uucp_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) os_uucp_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - os_uucp_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - os_uucp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) os_uucp_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" os_uucp_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_inactivity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(3)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_inactivity_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeInactiveDays"]/following-sibling::integer[1]/text()' -
)
    # expected result {'integer': 35}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_inactivity_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_inactivity_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "35" ]]; then
        /bin/echo "$(date -u) pwpolicy_account_inactivity_enforce passed (Result: $result_value, Expected: "{'integer': 35}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_inactivity_enforce passed (Result: $result_value, Expected: "{'integer': 35}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_account_inactivity_enforce failed (Result: $result_value, Expected: "{'integer': 35}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_inactivity_enforce failed (Result: $result_value, Expected: "{'integer': 35}")"
        else
            /bin/echo "$(date -u) pwpolicy_account_inactivity_enforce failed (Result: $result_value, Expected: "{'integer': 35}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_inactivity_enforce failed (Result: $result_value, Expected: "{'integer': 35}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_account_inactivity_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_account_inactivity_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_lockout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_lockout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_account_lockout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_account_lockout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_account_lockout_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-7
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_account_lockout_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_lockout_timeout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_lockout_timeout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_account_lockout_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_timeout_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_account_lockout_timeout_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_account_lockout_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_account_lockout_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_alpha_numeric_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_alpha_numeric_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "requireAlphanumeric" -c
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_alpha_numeric_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_alpha_numeric_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) pwpolicy_alpha_numeric_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_alpha_numeric_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_alpha_numeric_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_alpha_numeric_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_alpha_numeric_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_history_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_history_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 5 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_history_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_history_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_history_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_history_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_history_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_history_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_history_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_lower_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_lower_case_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="minimumAlphaCharactersLowerCase"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 1 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_lower_case_character_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_lower_case_character_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_lower_case_character_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_lower_case_character_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_lower_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_lower_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_lower_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_lower_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_lower_case_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_lower_case_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_max_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_max_lifetime_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' -
)
    # expected result {'integer': 60}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_max_lifetime_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_max_lifetime_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "60" ]]; then
        /bin/echo "$(date -u) pwpolicy_max_lifetime_enforce passed (Result: $result_value, Expected: "{'integer': 60}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_max_lifetime_enforce passed (Result: $result_value, Expected: "{'integer': 60}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}")"
        else
            /bin/echo "$(date -u) pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_max_lifetime_enforce failed (Result: $result_value, Expected: "{'integer': 60}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_max_lifetime_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_max_lifetime_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_minimum_length_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_minimum_length_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''.{15,}'\''")])' -
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_length_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_length_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) pwpolicy_minimum_length_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_length_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_length_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_minimum_length_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_length_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_minimum_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_minimum_lifetime_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMinimumLifetimeHours"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 24 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_lifetime_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_lifetime_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_minimum_lifetime_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_lifetime_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_minimum_lifetime_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_lifetime_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_minimum_lifetime_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_minimum_lifetime_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_minimum_lifetime_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_minimum_lifetime_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_simple_sequence_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_simple_sequence_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "allowSimple" -c
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_simple_sequence_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_simple_sequence_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) pwpolicy_simple_sequence_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_simple_sequence_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_simple_sequence_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_simple_sequence_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_simple_sequence_disable -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_special_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_special_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''(.*[^a-zA-Z0-9].*){1,}'\''")])' -
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_special_character_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_special_character_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) pwpolicy_special_character_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_special_character_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_special_character_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_special_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_special_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: pwpolicy_upper_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: pwpolicy_upper_case_character_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="minimumAlphaCharactersUpperCase"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 1 ) {print "yes"} else {print "no"}}'
)
    # expected result {'string': 'yes'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_upper_case_character_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_upper_case_character_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "yes" ]]; then
        /bin/echo "$(date -u) pwpolicy_upper_case_character_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - pwpolicy_upper_case_character_enforce passed (Result: $result_value, Expected: "{'string': 'yes'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) pwpolicy_upper_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_upper_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}")"
        else
            /bin/echo "$(date -u) pwpolicy_upper_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - pwpolicy_upper_case_character_enforce failed (Result: $result_value, Expected: "{'string': 'yes'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) pwpolicy_upper_case_character_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" pwpolicy_upper_case_character_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_ad_tracking_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_ad_tracking_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.AdLib')\
.objectForKey('forceLimitAdTracking').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_ad_tracking_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_ad_tracking_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_ad_tracking_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_ad_tracking_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_ad_tracking_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_ad_tracking_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_ad_tracking_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_ad_tracking_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_ad_tracking_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_ad_tracking_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_ad_tracking_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_ad_tracking_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_ad_tracking_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_afp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_afp_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AppleFileServer" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_afp_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_afp_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_afp_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_afp_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_afp_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_afp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_afp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_afp_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_afp_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_bluetooth_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18, AC-18(3)
# * SC-8
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_bluetooth_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_bluetooth_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_bluetooth_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_bluetooth_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) sysprefs_bluetooth_sharing_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_sharing_disable passed (Result: $result_value, Expected: "{'boolean': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}")"
        else
            /bin/echo "$(date -u) sysprefs_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_bluetooth_sharing_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_bluetooth_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_bluetooth_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_content_caching_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_content_caching_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowContentCaching').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_content_caching_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_content_caching_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) sysprefs_content_caching_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_content_caching_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_content_caching_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_content_caching_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) sysprefs_content_caching_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_content_caching_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_content_caching_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_content_caching_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_critical_update_install_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-2
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_critical_update_install_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('CriticalUpdateInstall').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_critical_update_install_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_critical_update_install_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_critical_update_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_critical_update_install_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_critical_update_install_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_critical_update_install_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_critical_update_install_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_diagnostics_reports_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * SC-7(10)
# * SI-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_diagnostics_reports_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo')\
.objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return("true")
} else {
    return("false")
}
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_diagnostics_reports_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_diagnostics_reports_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_diagnostics_reports_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_diagnostics_reports_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_diagnostics_reports_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_diagnostics_reports_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_diagnostics_reports_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_filevault_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SC-28, SC-28(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_filevault_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On."
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_filevault_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_filevault_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_filevault_enforce passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_filevault_enforce failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_filevault_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_filevault_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_find_my_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_find_my_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyDevice'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyFriends'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.icloud.managed')\
.objectForKey('DisableFMMiCloudSetting'))
  if ( pref1 == false && pref2 == false && pref3 == true ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_find_my_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_find_my_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_find_my_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_find_my_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_find_my_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_find_my_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_find_my_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_find_my_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_find_my_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_find_my_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_firewall_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | /usr/bin/grep -c "Firewall is enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_firewall_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_firewall_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_firewall_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_firewall_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_firewall_enable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_firewall_stealth_mode_enable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | /usr/bin/grep -c "Stealth mode enabled"
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_stealth_mode_enable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_stealth_mode_enable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_firewall_stealth_mode_enable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_firewall_stealth_mode_enable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_firewall_stealth_mode_enable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_guest_access_afp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_guest_access_afp_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'guestAccess = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_afp_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_afp_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_guest_access_afp_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_afp_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_afp_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_guest_access_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_afp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_guest_access_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_afp_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_afp_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_guest_access_afp_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_afp_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_guest_access_smb_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_smb_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_smb_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) sysprefs_guest_access_smb_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_smb_disable passed (Result: $result_value, Expected: "{'boolean': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}")"
        else
            /bin/echo "$(date -u) sysprefs_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_access_smb_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_guest_access_smb_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_guest_access_smb_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_guest_account_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_guest_account_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_account_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_account_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_guest_account_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_account_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_guest_account_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_guest_account_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_guest_account_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_improve_siri_dictation_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_improve_siri_dictation_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_improve_siri_dictation_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_improve_siri_dictation_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        /bin/echo "$(date -u) sysprefs_improve_siri_dictation_disable passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_improve_siri_dictation_disable passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            /bin/echo "$(date -u) sysprefs_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_improve_siri_dictation_disable failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_improve_siri_dictation_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_improve_siri_dictation_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_internet_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * AC-4
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_internet_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_internet_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_internet_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_internet_sharing_disable passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_internet_sharing_disable passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_internet_sharing_disable failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_internet_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_internet_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_location_services_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled
)
    # expected result {'boolean': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_location_services_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_location_services_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) sysprefs_location_services_disable passed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_location_services_disable passed (Result: $result_value, Expected: "{'boolean': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_location_services_disable failed (Result: $result_value, Expected: "{'boolean': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_location_services_disable failed (Result: $result_value, Expected: "{'boolean': 0}")"
        else
            /bin/echo "$(date -u) sysprefs_location_services_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_location_services_disable failed (Result: $result_value, Expected: "{'boolean': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_location_services_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_location_services_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_media_sharing_disabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_media_sharing_disabled ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults read com.apple.amp.mediasharingd | /usr/bin/grep -Ec '("public-sharing-enabled" = 0;|"home-sharing-enabled" = 0;)'
)
    # expected result {'integer': 2}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_media_sharing_disabled'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_media_sharing_disabled'))["exempt_reason"]
EOS
)

    if [[ $result_value == "2" ]]; then
        /bin/echo "$(date -u) sysprefs_media_sharing_disabled passed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_media_sharing_disabled passed (Result: $result_value, Expected: "{'integer': 2}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_media_sharing_disabled failed (Result: $result_value, Expected: "{'integer': 2}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_media_sharing_disabled failed (Result: $result_value, Expected: "{'integer': 2}")"
        else
            /bin/echo "$(date -u) sysprefs_media_sharing_disabled failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_media_sharing_disabled failed (Result: $result_value, Expected: "{'integer': 2}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_media_sharing_disabled does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_media_sharing_disabled -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_power_nap_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}'
)
    # expected result {'integer': 0}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_power_nap_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_power_nap_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "0" ]]; then
        /bin/echo "$(date -u) sysprefs_power_nap_disable passed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_power_nap_disable passed (Result: $result_value, Expected: "{'integer': 0}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}")"
        else
            /bin/echo "$(date -u) sysprefs_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_power_nap_disable failed (Result: $result_value, Expected: "{'integer': 0}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_power_nap_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_power_nap_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_rae_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_rae_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_rae_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_rae_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_rae_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_rae_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_rae_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screen_sharing_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screen_sharing_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screen_sharing_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_screen_sharing_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_screen_sharing_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_screen_sharing_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_screen_sharing_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_screensaver_timeout_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-11
# * IA-11
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_screensaver_timeout_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime').js
EOS
)
    # expected result {'integer': 1200}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screensaver_timeout_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screensaver_timeout_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1200" ]]; then
        /bin/echo "$(date -u) sysprefs_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'integer': 1200}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_screensaver_timeout_enforce passed (Result: $result_value, Expected: "{'integer': 1200}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'integer': 1200}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'integer': 1200}")"
        else
            /bin/echo "$(date -u) sysprefs_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'integer': 1200}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_screensaver_timeout_enforce failed (Result: $result_value, Expected: "{'integer': 1200}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_screensaver_timeout_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_screensaver_timeout_enforce -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_siri_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-20
# * CM-7, CM-7(1)
# * SC-7(10)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_siri_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.ironwood.support')\
.objectForKey('Ironwood Allowed').js
EOS
)
    # expected result {'string': 'false'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_siri_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_siri_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "false" ]]; then
        /bin/echo "$(date -u) sysprefs_siri_disable passed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_siri_disable passed (Result: $result_value, Expected: "{'string': 'false'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}")"
        else
            /bin/echo "$(date -u) sysprefs_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_siri_disable failed (Result: $result_value, Expected: "{'string': 'false'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_siri_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_siri_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_smbd_disable ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => true'
)
    # expected result {'integer': 1}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_smbd_disable'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_smbd_disable'))["exempt_reason"]
EOS
)

    if [[ $result_value == "1" ]]; then
        /bin/echo "$(date -u) sysprefs_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_smbd_disable passed (Result: $result_value, Expected: "{'integer': 1}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}")"
        else
            /bin/echo "$(date -u) sysprefs_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_smbd_disable failed (Result: $result_value, Expected: "{'integer': 1}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_smbd_disable does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_smbd_disable -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_time_server_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_time_server_configure ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS
)
    # expected result {'string': 'time-a.nist.gov,time-b.nist.gov'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_time_server_configure'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_time_server_configure'))["exempt_reason"]
EOS
)

    if [[ $result_value == "time-a.nist.gov,time-b.nist.gov" ]]; then
        /bin/echo "$(date -u) sysprefs_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_configure passed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}")"
        else
            /bin/echo "$(date -u) sysprefs_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_configure failed (Result: $result_value, Expected: "{'string': 'time-a.nist.gov,time-b.nist.gov'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_time_server_configure does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_time_server_configure -dict-add finding -bool NO
fi
    
#####----- Rule: sysprefs_time_server_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)
rule_arch=""
if [[ "$arch" == "$rule_arch" ]] || [[ -z "$rule_arch" ]]; then
    #echo 'Running the command to check the settings for: sysprefs_time_server_enforce ...' | tee -a "$audit_log"
    unset result_value
    result_value=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
)
    # expected result {'string': 'true'}


    # check to see if rule is exempt
    unset exempt
    unset exempt_reason

    exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_time_server_enforce'))["exempt"]
EOS
)
    exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_time_server_enforce'))["exempt_reason"]
EOS
)

    if [[ $result_value == "true" ]]; then
        /bin/echo "$(date -u) sysprefs_time_server_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
        /usr/bin/defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool NO
        /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_enforce passed (Result: $result_value, Expected: "{'string': 'true'}")"
    else
        if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
            /bin/echo "$(date -u) sysprefs_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}")"
        else
            /bin/echo "$(date -u) sysprefs_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool YES
            /usr/bin/logger "mSCP: cisv8 - sysprefs_time_server_enforce failed (Result: $result_value, Expected: "{'string': 'true'}") - Exemption Allowed (Reason: "$exempt_reason")"
            /bin/sleep 1
        fi
    fi


else
    /bin/echo "$(date -u) sysprefs_time_server_enforce does not apply to this architechture" | tee -a "$audit_log"
    /usr/bin/defaults write "$audit_plist" sysprefs_time_server_enforce -dict-add finding -bool NO
fi
    
lastComplianceScan=$(defaults read "$audit_plist" lastComplianceCheck)
/bin/echo "Results written to $audit_plist"

if [[ ! $check ]];then
    pause
fi

}

run_fix(){

if [[ ! -e "$audit_plist" ]]; then
    /bin/echo "Audit plist doesn't exist, please run Audit Check First" | tee -a "$audit_log"

    if [[ ! $fix ]]; then
        pause
        show_menus
        read_options
    else
        exit 1
    fi
fi

if [[ ! $fix ]]; then
    ask 'THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER. WOULD YOU LIKE TO CONTINUE? ' N

    if [[ $? != 0 ]]; then
        show_menus
        read_options
    fi
fi

# append to existing logfile
/bin/echo "$(date -u) Beginning remediation of non-compliant settings" >> "$audit_log"

# run mcxrefresh
/usr/bin/mcxrefresh -u $CURR_USER_UID


    
#####----- Rule: audit_auditd_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12, AU-12(1), AU-12(3)
# * AU-14(1)
# * AU-3, AU-3(1)
# * AU-8
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_auditd_enabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_auditd_enabled'))["exempt_reason"]
EOS
)

audit_auditd_enabled_audit_score=$($plb -c "print audit_auditd_enabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_auditd_enabled_audit_score == "true" ]]; then
        ask 'audit_auditd_enabled - Run the command(s)-> /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_auditd_enabled ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
        fi
    else
        /bin/echo 'Settings for: audit_auditd_enabled already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_auditd_enabled has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_aa_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_aa_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_aa_configure'))["exempt_reason"]
EOS
)

audit_flags_aa_configure_audit_score=$($plb -c "print audit_flags_aa_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_aa_configure_audit_score == "true" ]]; then
        ask 'audit_flags_aa_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,aa/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_aa_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]aa" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_aa_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_aa_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_ad_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12), AC-2(4)
# * AC-6(9)
# * AU-12
# * AU-2
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ad_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ad_configure'))["exempt_reason"]
EOS
)

audit_flags_ad_configure_audit_score=$($plb -c "print audit_flags_ad_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_ad_configure_audit_score == "true" ]]; then
        ask 'audit_flags_ad_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,ad/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_ad_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]ad" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_ad_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_ad_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_ex_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * CM-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ex_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_ex_configure'))["exempt_reason"]
EOS
)

audit_flags_ex_configure_audit_score=$($plb -c "print audit_flags_ex_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_ex_configure_audit_score == "true" ]]; then
        ask 'audit_flags_ex_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-ex" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-ex/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_ex_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-ex" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-ex/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_ex_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_ex_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fd_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fd_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fd_configure'))["exempt_reason"]
EOS
)

audit_flags_fd_configure_audit_score=$($plb -c "print audit_flags_fd_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fd_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fd_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fd/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_fd_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fd" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fd/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_fd_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_fd_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fm_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fm_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fm_configure'))["exempt_reason"]
EOS
)

audit_flags_fm_configure_audit_score=$($plb -c "print audit_flags_fm_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fm_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fm_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fm" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fm/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_fm_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fm" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fm/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_fm_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_fm_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fr_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fr_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fr_configure'))["exempt_reason"]
EOS
)

audit_flags_fr_configure_audit_score=$($plb -c "print audit_flags_fr_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fr_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fr_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fr/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_fr_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fr" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_fr_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_fr_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_fw_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(12)
# * AU-12
# * AU-2
# * AU-9
# * CM-5(1)
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fw_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_fw_configure'))["exempt_reason"]
EOS
)

audit_flags_fw_configure_audit_score=$($plb -c "print audit_flags_fw_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_fw_configure_audit_score == "true" ]]; then
        ask 'audit_flags_fw_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,-fw/'"'"' /etc/security/audit_control;/usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_fw_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*-fw" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,-fw/' /etc/security/audit_control;/usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_fw_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_fw_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_flags_lo_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17(1)
# * AC-2(12)
# * AU-12
# * AU-2
# * MA-4(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_lo_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_flags_lo_configure'))["exempt_reason"]
EOS
)

audit_flags_lo_configure_audit_score=$($plb -c "print audit_flags_lo_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_flags_lo_configure_audit_score == "true" ]]; then
        ask 'audit_flags_lo_configure - Run the command(s)-> /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '"'"'/^flags/ s/$/,lo/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_flags_lo_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/grep -qE "^flags.*[^-]lo" /etc/security/audit_control || /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_flags_lo_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_flags_lo_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: audit_retention_configure -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-11
# * AU-4

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_retention_configure'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('audit_retention_configure'))["exempt_reason"]
EOS
)

audit_retention_configure_audit_score=$($plb -c "print audit_retention_configure:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $audit_retention_configure_audit_score == "true" ]]; then
        ask 'audit_retention_configure - Run the command(s)-> /usr/bin/sed -i.bak '"'"'s/^expire-after.*/expire-after:7d/'"'"' /etc/security/audit_control; /usr/sbin/audit -s ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: audit_retention_configure ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/sed -i.bak 's/^expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s
        fi
    else
        /bin/echo 'Settings for: audit_retention_configure already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) audit_retention_configure has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_apple_mobile_file_integrity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * SI-3
# * SI-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_apple_mobile_file_integrity_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_apple_mobile_file_integrity_enforce'))["exempt_reason"]
EOS
)

os_apple_mobile_file_integrity_enforce_audit_score=$($plb -c "print os_apple_mobile_file_integrity_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_apple_mobile_file_integrity_enforce_audit_score == "true" ]]; then
        ask 'os_apple_mobile_file_integrity_enforce - Run the command(s)-> /usr/sbin/nvram boot-args="" ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_apple_mobile_file_integrity_enforce ...' | /usr/bin/tee -a "$audit_log"
            /usr/sbin/nvram boot-args=""
        fi
    else
        /bin/echo 'Settings for: os_apple_mobile_file_integrity_enforce already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_apple_mobile_file_integrity_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_firewall_log_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12
# * SC-7

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_firewall_log_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_firewall_log_enable'))["exempt_reason"]
EOS
)

os_firewall_log_enable_audit_score=$($plb -c "print os_firewall_log_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_firewall_log_enable_audit_score == "true" ]]; then
        ask 'os_firewall_log_enable - Run the command(s)-> /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_firewall_log_enable ...' | /usr/bin/tee -a "$audit_log"
            /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
        fi
    else
        /bin/echo 'Settings for: os_firewall_log_enable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_firewall_log_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_gatekeeper_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-14
# * CM-5
# * SI-3
# * SI-7(1), SI-7(15)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_gatekeeper_enable'))["exempt_reason"]
EOS
)

os_gatekeeper_enable_audit_score=$($plb -c "print os_gatekeeper_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_gatekeeper_enable_audit_score == "true" ]]; then
        ask 'os_gatekeeper_enable - Run the command(s)-> /usr/sbin/spctl --master-enable ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_gatekeeper_enable ...' | /usr/bin/tee -a "$audit_log"
            /usr/sbin/spctl --master-enable
        fi
    else
        /bin/echo 'Settings for: os_gatekeeper_enable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_gatekeeper_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_httpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_httpd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_httpd_disable'))["exempt_reason"]
EOS
)

os_httpd_disable_audit_score=$($plb -c "print os_httpd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_httpd_disable_audit_score == "true" ]]; then
        ask 'os_httpd_disable - Run the command(s)-> /bin/launchctl disable system/org.apache.httpd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_httpd_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/org.apache.httpd
        fi
    else
        /bin/echo 'Settings for: os_httpd_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_httpd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_nfsd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_nfsd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_nfsd_disable'))["exempt_reason"]
EOS
)

os_nfsd_disable_audit_score=$($plb -c "print os_nfsd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_nfsd_disable_audit_score == "true" ]]; then
        ask 'os_nfsd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.nfsd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_nfsd_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.nfsd
        fi
    else
        /bin/echo 'Settings for: os_nfsd_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_nfsd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_tftpd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_tftpd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_tftpd_disable'))["exempt_reason"]
EOS
)

os_tftpd_disable_audit_score=$($plb -c "print os_tftpd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_tftpd_disable_audit_score == "true" ]]; then
        ask 'os_tftpd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.tftpd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_tftpd_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.tftpd
        fi
    else
        /bin/echo 'Settings for: os_tftpd_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_tftpd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_time_server_enabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AU-12(1)
# * SC-45(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_time_server_enabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_time_server_enabled'))["exempt_reason"]
EOS
)

os_time_server_enabled_audit_score=$($plb -c "print os_time_server_enabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_time_server_enabled_audit_score == "true" ]]; then
        ask 'os_time_server_enabled - Run the command(s)-> /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_time_server_enabled ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist
        fi
    else
        /bin/echo 'Settings for: os_time_server_enabled already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_time_server_enabled has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: os_uucp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_uucp_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('os_uucp_disable'))["exempt_reason"]
EOS
)

os_uucp_disable_audit_score=$($plb -c "print os_uucp_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $os_uucp_disable_audit_score == "true" ]]; then
        ask 'os_uucp_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.uucp ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: os_uucp_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.uucp
        fi
    else
        /bin/echo 'Settings for: os_uucp_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) os_uucp_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_account_inactivity_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2(3)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_inactivity_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_account_inactivity_enforce'))["exempt_reason"]
EOS
)

pwpolicy_account_inactivity_enforce_audit_score=$($plb -c "print pwpolicy_account_inactivity_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_account_inactivity_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_account_inactivity_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: pwpolicy_account_inactivity_enforce ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        /bin/echo 'Settings for: pwpolicy_account_inactivity_enforce already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) pwpolicy_account_inactivity_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_lower_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_lower_case_character_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_lower_case_character_enforce'))["exempt_reason"]
EOS
)

pwpolicy_lower_case_character_enforce_audit_score=$($plb -c "print pwpolicy_lower_case_character_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_lower_case_character_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_lower_case_character_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: pwpolicy_lower_case_character_enforce ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        /bin/echo 'Settings for: pwpolicy_lower_case_character_enforce already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) pwpolicy_lower_case_character_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_minimum_lifetime_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_lifetime_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_minimum_lifetime_enforce'))["exempt_reason"]
EOS
)

pwpolicy_minimum_lifetime_enforce_audit_score=$($plb -c "print pwpolicy_minimum_lifetime_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_minimum_lifetime_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_minimum_lifetime_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: pwpolicy_minimum_lifetime_enforce ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        /bin/echo 'Settings for: pwpolicy_minimum_lifetime_enforce already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) pwpolicy_minimum_lifetime_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: pwpolicy_upper_case_character_enforce -----#####
## Addresses the following NIST 800-53 controls: 
# * IA-5(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_upper_case_character_enforce'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('pwpolicy_upper_case_character_enforce'))["exempt_reason"]
EOS
)

pwpolicy_upper_case_character_enforce_audit_score=$($plb -c "print pwpolicy_upper_case_character_enforce:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $pwpolicy_upper_case_character_enforce_audit_score == "true" ]]; then
        ask 'pwpolicy_upper_case_character_enforce - Run the command(s)-> /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: pwpolicy_upper_case_character_enforce ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
        fi
    else
        /bin/echo 'Settings for: pwpolicy_upper_case_character_enforce already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) pwpolicy_upper_case_character_enforce has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_afp_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_afp_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_afp_disable'))["exempt_reason"]
EOS
)

sysprefs_afp_disable_audit_score=$($plb -c "print sysprefs_afp_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_afp_disable_audit_score == "true" ]]; then
        ask 'sysprefs_afp_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.AppleFileServer ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_afp_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.AppleFileServer
        fi
    else
        /bin/echo 'Settings for: sysprefs_afp_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_afp_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_bluetooth_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-18(4)
# * AC-3
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_bluetooth_sharing_disable'))["exempt_reason"]
EOS
)

sysprefs_bluetooth_sharing_disable_audit_score=$($plb -c "print sysprefs_bluetooth_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_bluetooth_sharing_disable_audit_score == "true" ]]; then
        ask 'sysprefs_bluetooth_sharing_disable - Run the command(s)-> /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_bluetooth_sharing_disable ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        fi
    else
        /bin/echo 'Settings for: sysprefs_bluetooth_sharing_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_bluetooth_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_firewall_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-4
# * CM-7, CM-7(1)
# * SC-7, SC-7(12)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_enable'))["exempt_reason"]
EOS
)

sysprefs_firewall_enable_audit_score=$($plb -c "print sysprefs_firewall_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_firewall_enable_audit_score == "true" ]]; then
        ask 'sysprefs_firewall_enable - Run the command(s)-> /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_firewall_enable ...' | /usr/bin/tee -a "$audit_log"
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
        fi
    else
        /bin/echo 'Settings for: sysprefs_firewall_enable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_firewall_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_firewall_stealth_mode_enable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7, SC-7(16)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_stealth_mode_enable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_firewall_stealth_mode_enable'))["exempt_reason"]
EOS
)

sysprefs_firewall_stealth_mode_enable_audit_score=$($plb -c "print sysprefs_firewall_stealth_mode_enable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_firewall_stealth_mode_enable_audit_score == "true" ]]; then
        ask 'sysprefs_firewall_stealth_mode_enable - Run the command(s)-> /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_firewall_stealth_mode_enable ...' | /usr/bin/tee -a "$audit_log"
            /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
        fi
    else
        /bin/echo 'Settings for: sysprefs_firewall_stealth_mode_enable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_firewall_stealth_mode_enable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_guest_access_smb_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-2, AC-2(9)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_smb_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_guest_access_smb_disable'))["exempt_reason"]
EOS
)

sysprefs_guest_access_smb_disable_audit_score=$($plb -c "print sysprefs_guest_access_smb_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_guest_access_smb_disable_audit_score == "true" ]]; then
        ask 'sysprefs_guest_access_smb_disable - Run the command(s)-> /usr/sbin/sysadminctl -smbGuestAccess off ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_guest_access_smb_disable ...' | /usr/bin/tee -a "$audit_log"
            /usr/sbin/sysadminctl -smbGuestAccess off
        fi
    else
        /bin/echo 'Settings for: sysprefs_guest_access_smb_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_guest_access_smb_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_location_services_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)
# * SC-7(10)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_location_services_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_location_services_disable'))["exempt_reason"]
EOS
)

sysprefs_location_services_disable_audit_score=$($plb -c "print sysprefs_location_services_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_location_services_disable_audit_score == "true" ]]; then
        ask 'sysprefs_location_services_disable - Run the command(s)-> /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_location_services_disable ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /bin/launchctl kickstart -k system/com.apple.locationd
        fi
    else
        /bin/echo 'Settings for: sysprefs_location_services_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_location_services_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_media_sharing_disabled -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_media_sharing_disabled'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_media_sharing_disabled'))["exempt_reason"]
EOS
)

sysprefs_media_sharing_disabled_audit_score=$($plb -c "print sysprefs_media_sharing_disabled:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_media_sharing_disabled_audit_score == "true" ]]; then
        ask 'sysprefs_media_sharing_disabled - Run the command(s)-> /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.amp.mediasharingd public-sharing-enabled -int 0
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0
/usr/bin/pkill -9 AMPLibraryAgent
/usr/bin/pkill -9 mediasharingd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_media_sharing_disabled ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.amp.mediasharingd public-sharing-enabled -int 0
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0
/usr/bin/pkill -9 AMPLibraryAgent
/usr/bin/pkill -9 mediasharingd
        fi
    else
        /bin/echo 'Settings for: sysprefs_media_sharing_disabled already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_media_sharing_disabled has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_power_nap_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * CM-7, CM-7(1)

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_power_nap_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_power_nap_disable'))["exempt_reason"]
EOS
)

sysprefs_power_nap_disable_audit_score=$($plb -c "print sysprefs_power_nap_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_power_nap_disable_audit_score == "true" ]]; then
        ask 'sysprefs_power_nap_disable - Run the command(s)-> /usr/bin/pmset -a powernap 0 ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_power_nap_disable ...' | /usr/bin/tee -a "$audit_log"
            /usr/bin/pmset -a powernap 0
        fi
    else
        /bin/echo 'Settings for: sysprefs_power_nap_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_power_nap_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_rae_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_rae_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_rae_disable'))["exempt_reason"]
EOS
)

sysprefs_rae_disable_audit_score=$($plb -c "print sysprefs_rae_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_rae_disable_audit_score == "true" ]]; then
        ask 'sysprefs_rae_disable - Run the command(s)-> /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_rae_disable ...' | /usr/bin/tee -a "$audit_log"
            /usr/sbin/systemsetup -setremoteappleevents off
/bin/launchctl disable system/com.apple.AEServer
        fi
    else
        /bin/echo 'Settings for: sysprefs_rae_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_rae_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_screen_sharing_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screen_sharing_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_screen_sharing_disable'))["exempt_reason"]
EOS
)

sysprefs_screen_sharing_disable_audit_score=$($plb -c "print sysprefs_screen_sharing_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_screen_sharing_disable_audit_score == "true" ]]; then
        ask 'sysprefs_screen_sharing_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.screensharing ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_screen_sharing_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.screensharing
        fi
    else
        /bin/echo 'Settings for: sysprefs_screen_sharing_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_screen_sharing_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
#####----- Rule: sysprefs_smbd_disable -----#####
## Addresses the following NIST 800-53 controls: 
# * AC-17
# * AC-3

# check to see if rule is exempt
unset exempt
unset exempt_reason

exempt=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_smbd_disable'))["exempt"]
EOS
)

exempt_reason=$(/usr/bin/osascript -l JavaScript << EOS 2>/dev/null
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('org.cisv8.audit').objectForKey('sysprefs_smbd_disable'))["exempt_reason"]
EOS
)

sysprefs_smbd_disable_audit_score=$($plb -c "print sysprefs_smbd_disable:finding" $audit_plist)
if [[ ! $exempt == "1" ]] || [[ -z $exempt ]];then
    if [[ $sysprefs_smbd_disable_audit_score == "true" ]]; then
        ask 'sysprefs_smbd_disable - Run the command(s)-> /bin/launchctl disable system/com.apple.smbd ' N
        if [[ $? == 0 ]]; then
            /bin/echo 'Running the command to configure the settings for: sysprefs_smbd_disable ...' | /usr/bin/tee -a "$audit_log"
            /bin/launchctl disable system/com.apple.smbd
        fi
    else
        /bin/echo 'Settings for: sysprefs_smbd_disable already configured, continuing...' | /usr/bin/tee -a "$audit_log"
    fi
elif [[ ! -z "$exempt_reason" ]];then
    /bin/echo "$(date -u) sysprefs_smbd_disable has an exemption, remediation skipped (Reason: "$exempt_reason")" | /usr/bin/tee -a "$audit_log"
fi
    
/bin/echo "$(date -u) Remediation complete" >> "$audit_log"

}

zparseopts -D -E -check=check -fix=fix -stats=stats -compliant=compliant_opt -non_compliant=non_compliant_opt -reset=reset

if [[ $reset ]]; then reset_plist; fi

if [[ $check ]] || [[ $fix ]] || [[ $stats ]] || [[ $compliant_opt ]] || [[ $non_compliant_opt ]]; then
    if [[ $fix ]]; then run_fix; fi
    if [[ $check ]]; then run_scan; fi
    if [[ $stats ]];then generate_stats; fi
    if [[ $compliant_opt ]];then compliance_count "compliant"; fi
    if [[ $non_compliant_opt ]];then compliance_count "non-compliant"; fi
else
    while true; do
        show_menus
        read_options
    done
fi
    