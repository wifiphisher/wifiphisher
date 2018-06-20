#!/usr/bin/env bash

set -o errexit
set -o pipefail
#set -o xtrace

main(){
  local current_version
  current_version=$(grep -i "version =" setup.py |
    cut -d= -f2 |cut -d"\"" -f2)
  echo -e "\u25b7\u25b7 Current Version = \e[91m${current_version}\e[39m"

  local new_version
  local major
  local minor
  local patch
  major=$(echo "${current_version}" |cut -d"." -f1)
  minor=$(echo "${current_version}" |cut -d"." -f2)
  patch=$(echo "${current_version}" |cut -d"." -f3)

  local logs
  logs="$(git log "$(git describe --tags --abbrev=0)"..HEAD)"

  if echo "${logs}" | grep -iq "breaking change";then
    echo -e "\e[41mBreaking Change Detected!\e[49m"
    new_version="$((major + 1)).0.0"
  elif echo "${logs}" | grep -q "feat:"; then
    echo -e "\e[41mNew Feature Detected!\e[49m"
    new_version="${major}.$((minor + 1)).0"
  elif echo "${logs}" | grep -q "fix:"; then
    echo -e "\e[41mNew Fix Detected!\e[49m"
    new_version="${major}.${minor}.$((patch + 1))"
  else
    echo -e "\e[41mNo Version Change!\e[49m"
    exit 0
  fi

  echo -e "\u25b7\u25b7 New Version = \e[92m${new_version}\e[39m"

  echo -e "\u25b7\u25b7 Changing Version Numbers"
  #sed -ie "s/$current_version/$new_version/" setup.py
  echo -e "\e[92m\u2714\e[39m Updated all Version Numbers"

  echo -e "\e[93m\u2744\e[0m Generating New Changelog"
  local name_url="https://frightanic.com/goodies_content/docker-names.php"
  local code_name=$(curl -s "$name_url")
  echo -e "\u25b7\u25b7 New Version Code Name Is \e[42m\e[30m${code_name}\
  \e[39m\e[49m"
  echo "${new_version} ${code_name} ($(date +"%F"))" \
    >> temp_changelog.md
  printf '=%.0s' {1..60} >> temp_changelog.md
  echo >> temp_changelog.md

  if echo "${logs}" | grep -iq "breaking change"; then
    echo "Breaking Change:" >> temp_changelog.md
    echo "-----------------" >> temp_changelog.md
    echo "${logs}" | grep -i "breaking change:" | cut -d: -f2 | sed 's/^ //' \
      >> temp_changelog.md
    echo >> temp_changelog.md
  fi

  local commit_hashes
  local message
  commit_hashes="$(git rev-list "$(git describe --tags --abbrev=0)"..HEAD \
    --no-merges)"

  if echo "${logs}" | grep -q "feat:"; then
    echo "New Features:" >> temp_changelog.md
    echo "-----------------" >> temp_changelog.md

    for hash in $commit_hashes;do
      message=$(git log -n 1 --pretty=format:%s "${hash}")
      if [[ "${message}" =~ ^feat:.*$ ]];then
        echo "* $(echo "${message}" | cut -d: -f2 ) ${hash}" \
          >> temp_changelog.md
      fi
    done
    echo >> temp_changelog.md
  fi

  if echo "${logs}" | grep -q "fix:"; then
    echo "Bug Fixes:" >> temp_changelog.md
    echo "-----------------" >> temp_changelog.md
    for hash in $commit_hashes;do
      message=$(git log -n 1 --pretty=format:%s "${hash}")
      if [[ $message =~ ^fix:.*$ ]];then
        echo "* $(echo "${message}" | cut -d: -f2 ) ${hash}" \
           >>  temp_changelog.md
      fi
    done
    echo >> temp_changelog.md
  fi

  echo -e "$(cat temp_changelog.md)\n$(cat changelog.md)" > changelog.md
  rm temp_changelog.md

  echo -e "\e[92m\u2714\e[39m New Changelog generated"
  echo -e "\e[93m\u2744\e[0m Uploading to Github"
  #git config --global user.name "release-bot"
  #git config --global user.email "release-bot@github.com"
  #git add wifiphisher/ setup.py
  #git commit -m "chore:change release to ${new_version}"
  #git tag -a "v$new_version" -m "v$new_version"
  #git push --tags --dry-run
  #git push --dry-run

}

main
