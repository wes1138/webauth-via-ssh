CONFIGS   := sshd_config empty authorized_keys_script.sh start-sshd.sh
KEYS      := key-dsa key-rsa
# KEYS      := key-dsa key-rsa key-ecdsa key-ed25519
# make list of "HostKey" strings for later use by sed:
HKSTR := $(shell echo $(KEYS) | sed -e 's/ /\\n/g')
HKSTR := $(subst key-,HostKey $(shell pwd)/key-,$(HKSTR))

# sshd_config variables:
LISTEN_ADDRv4  ?= 0.0.0.0
LISTEN_ADDRv6  ?= ::
PID_FILE       ?= /tmp/.ssh-for-git.pid
AKSCRIPT       ?= $(shell pwd)/authorized_keys_script.sh
SSH_USER       ?= $(shell whoami)
EMPTYAUTHKEYS  ?= $(shell pwd)/empty

# authorized_keys_script variables:
FLATFILE   ?= $(shell pwd)/db-of-keys
TOKENGEN   ?= $(shell readlink -f "$(shell pwd)/../auth-modules/token-gen")
SSHOPTS    ?= no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty

# start-sshd.sh -- just have to set path to patched sshd.
# ******* YOU WILL ALMOST CERTAINLY WANT TO CHANGE THIS: *******
PATCHEDSSHD ?= $(HOME)/repos/others/openssh-for-git/sshd

.PHONY : all
all : $(CONFIGS) $(KEYS)

# TODO: could make the sed commands a little more robust
sshd_config : sshd_config.in
	sed -e 's|^\(ListenAddress\) @LISTEN_ADDRv4|\1 $(LISTEN_ADDRv4)|' \
		-e 's|^\(ListenAddress\) @LISTEN_ADDRv6|\1 $(LISTEN_ADDRv6)|' \
		-e 's|^\(PidFile\) @PID_FILE|\1 $(PID_FILE)|' \
		-e 's|^@HOSTKEYS|$(HKSTR)|' \
		-e 's|^\(AuthorizedKeysScript\) @AKSCRIPT|\1 $(AKSCRIPT)|' \
		-e 's|^\(AuthorizedKeysFile\) @EMPTYAUTHKEYS|\1 $(EMPTYAUTHKEYS)|' \
		-e 's|^\(AllowUsers\) @SSH_USER|\1 $(SSH_USER)|' $< > $@ || \
		rm $@

authorized_keys_script.sh : authorized_keys_script.sh.in
	sed -e 's|^\(database\)=@FLATFILE|\1="$(FLATFILE)"|' \
		-e 's|^\(tokengen\)=@TOKENGEN|\1="$(TOKENGEN)"|' \
		-e 's|^\(sshopts\)=@SSHOPTS|\1="$(SSHOPTS)"|' $< > $@ || \
		rm $@
	[[ -f $@ ]] && chmod 0700 $@

start-sshd.sh : start-sshd.sh.in
	sed -e 's|^@PATCHEDSSHD|$(PATCHEDSSHD)|' $< > $@ || rm $@
	[[ -f $@ ]] && chmod 0700 $@

$(KEYS) : key-% :
	ssh-keygen -f $@ -t $* -q -N ""

empty :
	echo "" > ./empty
	chmod 0600 ./empty

.PHONY : clean
clean :
	rm -f $(CONFIGS)

.PHONY : superclean
superclean : clean
	rm -f $(KEYS) $(patsubst %,%.pub,$(KEYS))

# vim:ft=make:foldmethod=marker:foldmarker={{{,}}}

