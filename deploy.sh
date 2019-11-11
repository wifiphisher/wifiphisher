#!/usr/bin/env bash

set -o errexit
set -o pipefail
#set -o xtrace

main(){
  git checkout --quiet master
  local current_version
  current_version=$(grep -i "version =" setup.py |
    cut -d= -f2 | tr -d "\" ")
  echo -e "\\u25b7\\u25b7 Current Version = \\e[91m${current_version}\\e[39m"

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
    echo -e "\\e[41mBreaking Change Detected!\\e[49m"
    new_version="$((major + 1)).0.0"
  elif echo "${logs}" | grep -q "feat:"; then
    echo -e "\\e[41mNew Feature Detected!\\e[49m"
    new_version="${major}.$((minor + 1)).0"
  elif echo "${logs}" | grep -q "fix:"; then
    echo -e "\\e[41mNew Fix Detected!\\e[49m"
    new_version="${major}.${minor}.$((patch + 1))"
  else
    echo -e "\\e[41mNo Version Change!\\e[49m"
    exit 0
  fi

  echo -e "\\u25b7\\u25b7 New Version = \\e[92m${new_version}\\e[39m"

  echo -e "\\u25b7\\u25b7 Changing Version Numbers"
  sed -i "s/$current_version/$new_version/" setup.py
  sed -i "s/$current_version/$new_version/" wifiphisher/pywifiphisher.py

  echo -e "\\e[93m\\u2744\\e[0m Generating New Changelog"
  local name_url="https://frightanic.com/goodies_content/docker-names.php"
  local code_name
  code_name="$(curl -s "$name_url")"
  echo -e "\\u25b7\\u25b7 New Version Code Name Is \\e[42m\\e[30m${code_name}\
\\e[39m\\e[49m"
  echo "${new_version} ${code_name} ($(date +"%F"))" >> temp_changelog.md
  echo "=====" >> temp_changelog.md
  echo >> temp_changelog.md

  if echo "${logs}" | grep -iq "breaking change"; then
    echo "Breaking Change" >> temp_changelog.md
    echo "----" >> temp_changelog.md
    echo "${logs}" | grep -i 'breaking change:' | cut -d: -f2 |
    sed 's/^ //' >> temp_changelog.md
    echo >> temp_changelog.md
  fi

  local commit_hashes
  local message
  commit_hashes="$(git rev-list "$(git describe --tags --abbrev=0)"..HEAD \
    --no-merges)"

  if echo "${logs}" | grep -q "feat:"; then
    echo "New Features:" >> temp_changelog.md
    echo "-----" >> temp_changelog.md

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
    echo "-----" >> temp_changelog.md
    for hash in $commit_hashes;do
      message=$(git log -n 1 --pretty=format:%s "${hash}")
      if [[ $message =~ ^fix:.*$ ]];then
        echo "* $(echo "${message}" | cut -d: -f2 ) ${hash}" \
           >>  temp_changelog.md
      fi
    done
    echo >> temp_changelog.md
  fi

  echo -e "\\e[93m\\u2744\\e[0m Uploading to Github"
  git config --global user.name "release-bot"
  git config --global user.email "release-bot@github.com"
  local github_url="https://${GH_TOKEN}@github.com/wifiphisher/\
  wifiphisher.git"
  git remote add new "${github_url// /}" 
  git add wifiphisher/pywifiphisher.py setup.py changelog.md > /dev/null
  git commit -m "chore:change release to ${new_version}" --quiet
  git tag -a "v$new_version" -m "v$new_version"
  git push new master --quiet
  git push new --tags --quiet

  # the sed in the data section removes all end of file ($) abd repleaces
  # it with \n since json can only be only line
  curl --silent --show-error -H "Authorization: token ${GH_TOKEN}" \
  https://api.github.com/repos/wifiphisher/wifiphisher/releases -d \
  "{
    \"tag_name\": \"${new_version}\",
    \"name\": \"${new_version} ${code_name}\",
    \"body\": \"$(sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g' temp_changelog.md)\",
    \"draft\": false,
    \"prerelease\": false
  }" > /dev/null

  echo -e "$(cat temp_changelog.md)\\n\\n$(cat changelog.md)" > changelog.md

  echo -e "\\u25b7\\u25b7 Uploading to PYPI"
  python setup.py sdist > /dev/null
  twine upload dist/* -u "${PYPI_USERNAME}" -p "${PYPI_PASS}" > /dev/null
}

main
