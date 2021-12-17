#!/bin/bash

# install dependencies
# apt-get -y install uuid openjdk-8-jre

#add user
useradd keycloak


# install keycloak
KEYCLOAK_VERSION=15.0.2

curl -L -o keycloak-${KEYCLOAK_VERSION}.tar.gz https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz
tar -zxf   keycloak-${KEYCLOAK_VERSION}.tar.gz
mv         keycloak-${KEYCLOAK_VERSION} /opt/keycloak
rm -rf     keycloak-${KEYCLOAK_VERSION}.tar.gz
mkdir -p /var/run/keycloak
chown -R keycloak: /opt/keycloak /var/run/keycloak

cat << EOF > /tmp/keycloak.service
[Unit]
Description=The KeyCloak Authentication Server
After=syslog.target network.target
Before=nginx.service

[Service]
Environment="LAUNCH_JBOSS_IN_BACKGROUND=1"
User=keycloak
LimitNOFILE=102642
PIDFile=/var/run/keycloak/keycloak.pid
ExecStart=/opt/keycloak/bin/standalone.sh -b 0.0.0.0 -Djboss.socket.binding.port-offset=100

[Install]
WantedBy=multi-user.target
EOF
mv /tmp/keycloak.service /usr/lib/systemd/system/
systemctl daemon-reload
systemctl enable keycloak


# bootstrap nginx config
uuid > .kc_secret
cat .kc_secret
client_secret=$(cat .kc_secret)
user_name=nginx-user
user_pass=password
realm=nginx
client=nginx-plus
admin_pass=password

keycloak /opt/keycloak/bin/add-user-keycloak.sh -u admin -p ${admin_pass}
systemctl start keycloak
sleep 10
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin --password ${admin_pass}
/opt/keycloak/bin/kcadm.sh create realms -s realm=${realm} -s enabled=true
/opt/keycloak/bin/kcadm.sh create users -r ${realm} -s username=${user_name} -s enabled=true
/opt/keycloak/bin/kcadm.sh set-password -r ${realm} --username ${user_name} --new-password ${user_pass}
output=$(/opt/keycloak/bin/kcadm.sh create clients -r ${realm} -s clientId=${client} -s enabled=true -s clientAuthenticatorType=client-secret -s secret=${client_secret} -s redirectUris='["https://192.168.193.4:443/_codexch","https://192.168.193.4:443/_logout"]' -s directAccessGrantsEnabled=true -s webOrigins='[]' 2>&1)
if [ $? -ne 0 ]; then
    echo "adding client failed"
fi
client_id=$(echo $output | cut -d"'" -f 2)
/opt/keycloak/bin/kcadm.sh create clients/${client_id}/roles -r ${realm} -s name=nginx-keycloak-role
/opt/keycloak/bin/kcadm.sh add-roles -r ${realm} --uusername ${user_name} --cclientid ${client}  --rolename nginx-keycloak-role
