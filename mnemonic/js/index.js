(function () {

    const mnemonic = new Mnemonic("english");
    let bip32RootKey = null;
    let bip32ExtendedKey = null;
    let network = bitcoin.networks.microbitcoin;
    const addressRowTemplate = $("#address-row-template");

    let showIndex = true;
    let showAddress = true;
    let showPubKey = true;
    let showPrivKey = true;

    let phraseChangeTimeoutEvent = null;

    let DOM = {};
    DOM.network = $(".network");
    DOM.phraseNetwork = $("#network-phrase");
    DOM.phrase = $(".phrase");
    DOM.passphrase = $(".passphrase");
    DOM.generate = $(".generate");
    DOM.rootKey = $(".root-key");
    DOM.rootKeyQr = $("#root-key-qr");
    DOM.extendedPrivKey = $(".extended-priv-key");
    DOM.extendedPubKey = $(".extended-pub-key");
    DOM.extendedPrivKeyQr = $("#extended-priv-key-qr");
    DOM.extendedPubKeyQr = $("#extended-pub-key-qr");
    DOM.bip32tab = $("#bip32-tab");
    DOM.bip44tab = $("#bip44-tab");
    DOM.bip32panel = $("#bip32");
    DOM.bip44panel = $("#bip44");
    DOM.bip32path = $("#bip32-path");
    DOM.bip44path = $("#bip44-path");
    DOM.bip44purpose = $("#bip44 .purpose");
    DOM.bip44coin = $("#bip44 .coin");
    DOM.bip44account = $("#bip44 .account");
    DOM.bip44change = $("#bip44 .change");
    DOM.strength = $(".strength");
    DOM.addresses = $(".addresses");
    DOM.rowsToAdd = $(".rows-to-add");
    DOM.more = $(".more");
    DOM.feedback = $(".feedback");
    DOM.tab = $(".derivation-type a");
    DOM.indexToggle = $(".index-toggle");
    DOM.addressToggle = $(".address-toggle");
    DOM.publicKeyToggle = $(".public-key-toggle");
    DOM.privateKeyToggle = $(".private-key-toggle");

    let derivationPath = $(".tab-pane.active .path").val();

    function init() {
        // Events
        DOM.network.on("change", networkChanged);
        DOM.phrase.on("input", delayedPhraseChanged);
        DOM.passphrase.on("input", delayedPhraseChanged);
        DOM.generate.on("click", generateClicked);
        DOM.more.on("click", showMore);
        DOM.bip32path.on("input", bip32Changed);
        DOM.bip44purpose.on("input", bip44Changed);
        DOM.bip44coin.on("input", bip44Changed);
        DOM.bip44account.on("input", bip44Changed);
        DOM.bip44change.on("input", bip44Changed);
        DOM.tab.on("click", tabClicked);
        DOM.indexToggle.on("click", toggleIndexes);
        DOM.addressToggle.on("click", toggleAddresses);
        DOM.publicKeyToggle.on("click", togglePublicKeys)
        DOM.privateKeyToggle.on("click", togglePrivateKeys);
        disableForms();
        hidePending();
        hideValidationError();
        populateNetworkSelect();
    }

    // Event handlers

    function networkChanged(e) {
        let network = e.target.value;
        networks[network].onSelect();
        setBip44DerivationPath();
        delayedPhraseChanged();
    }

    function delayedPhraseChanged() {
        hideValidationError();
        showPending();
        if (phraseChangeTimeoutEvent != null) {
            clearTimeout(phraseChangeTimeoutEvent);
        }
        phraseChangeTimeoutEvent = setTimeout(phraseChanged, 400);
    }

    function phraseChanged() {
        showPending();
        hideValidationError();
        // Get the mnemonic phrase
        let phrase = DOM.phrase.val();
        let passphrase = DOM.passphrase.val();

        // Get the derivation path
        let errorText = findDerivationPathErrors();
        if (errorText) {
            showValidationError(errorText);
            return;
        }
        // Calculate and display
        calcBip32Seed(phrase, passphrase, derivationPath);
        displayBip32Info();
        hidePending();
    }

    function generateClicked() {
        clearDisplay();
        showPending();
        setTimeout(function () {
            let phrase = generateRandomPhrase();
            if (!phrase) {
                return;
            }
            phraseChanged();
        }, 50);
    }

    function tabClicked(e) {
        let activePath = $(e.target.getAttribute("href") + " .path");
        derivationPath = activePath.val();
        derivationChanged();
    }

    function derivationChanged() {
        delayedPhraseChanged();
    }

    function bip32Changed() {
        derivationPath = DOM.bip32path.val();
        derivationChanged();
    }

    function bip44Changed() {
        setBip44DerivationPath();
        derivationChanged();
    }

    function toggleIndexes() {
        showIndex = !showIndex;
        $("td.index span").toggleClass("invisible");
    }

    function toggleAddresses() {
        showAddress = !showAddress;
        $("td.address a").toggleClass("invisible");
    }

    function togglePublicKeys() {
        showPubKey = !showPubKey;
        $("td.pubkey span").toggleClass("invisible");
    }

    function togglePrivateKeys() {
        showPrivKey = !showPrivKey;
        $("td.privkey a").toggleClass("invisible");
    }

    // Private methods

    function generateRandomPhrase() {
        if (!hasStrongRandom()) {
            let errorText = "This browser does not support strong randomness";
            showValidationError(errorText);
            return;
        }
        let numWords = parseInt(DOM.strength.val());
        let strength = numWords / 3 * 32;
        let words = mnemonic.generate(strength);
        DOM.phrase.val(words);
        return words;
    }

    function calcBip32Seed(phrase, passphrase, path) {
        let seed = mnemonic.toSeed(makeProperPhrase(phrase), passphrase);
        bip32RootKey = bitcoin.HDNode.fromSeedHex(seed, network);
        bip32ExtendedKey = bip32RootKey;
        // Derive the key from the path
        let pathBits = path.split("/");
        for (let i = 0; i < pathBits.length; i++) {
            let bit = pathBits[i];
            let index = parseInt(bit);
            if (isNaN(index)) {
                continue;
            }
            let hardened = bit[bit.length - 1] == "'";
            if (hardened) {
                bip32ExtendedKey = bip32ExtendedKey.deriveHardened(index);
            }
            else {
                bip32ExtendedKey = bip32ExtendedKey.derive(index);
            }
        }
    }

    function showValidationError(errorText) {
        DOM.feedback
            .text(errorText)
            .show();
    }

    function hideValidationError() {
        DOM.feedback
            .text("")
            .hide();
    }

    function makeProperPhrase(phrase) {
        // TODO make this right
        // Preprocess the words
        phrase = mnemonic.normalizeString(phrase);
        let parts = phrase.split(" ");
        let proper = [];
        for (let i = 0; i < parts.length; i++) {
            let part = parts[i];
            if (part.length > 0) {
                // TODO check that lowercasing is always valid to do
                proper.push(part.toLowerCase());
            }
        }
        // TODO some levenstein on the words
        return proper.join(' ');
    }

    function findPhraseErrors(phrase) {
        properPhrase = makeProperPhrase(phrase);
        // Check the words are valid
        let isValid = mnemonic.check(properPhrase);
        if (!isValid) {
            return "Invalid mnemonic";
        }
        return false;
    }

    function findDerivationPathErrors(path) {
        // TODO
        return false;
    }

    function displayBip32Info() {
        // Display the key
        let rootKey = bip32RootKey.toBase58();
        DOM.rootKey.val(rootKey);
        DOM.rootKeyQr.html("")
        DOM.rootKeyQr.qrcode(rootKey);
        let extendedPrivKey = bip32ExtendedKey.toBase58();
        DOM.extendedPrivKey.val(extendedPrivKey);
        DOM.extendedPrivKeyQr.html("")
        DOM.extendedPrivKeyQr.qrcode(extendedPrivKey);
        let extendedPubKey = bip32ExtendedKey.toBase58(false);
        DOM.extendedPubKey.val(extendedPubKey);
        DOM.extendedPubKeyQr.html("")
        DOM.extendedPubKeyQr.qrcode(extendedPubKey);
        // Display the addresses and privkeys
        clearAddressesList();
        displayAddresses(0, 20);
    }

    function displayAddresses(start, total) {
        for (let i = 0; i < total; i++) {
            let index = i + start;
            new TableRow(index);
        }
    }

    function TableRow(index) {

        function init() {
            calculateValues();
        }

        function calculateValues() {
            setTimeout(function () {
                let key = bip32ExtendedKey.derive(index);
                let address;
                if (!network.ethereum) {
                    address = key.getAddress().toString();
                }
                else {
                    let pubData = new bitcoin.ECKey(key.privKey.d, false).pub.toHex();
                    let buffer = new ArrayBuffer(64);
                    let view = new Uint8Array(buffer);
                    let offset = 0;
                    for (let i = 2; i < pubData.length; i += 2) {
                        view[offset++] = parseInt(pubData.substr(i, 2), 16);
                    }
                    let addressHex = keccak_256(buffer).substr(24).toLowerCase();
                    let checksum = keccak_256(addressHex)
                    let address = "0x";
                    for (let i = 0; i < addressHex.length; i++) {
                        if (parseInt(checksum[i], 16) >= 8) {
                            address += addressHex[i].toUpperCase()
                        } else {
                            address += addressHex[i]
                        }
                    }
                }
                let privkey;

                let pubkey = key.pubKey.toHex();
                if (!network.ethereum) {
                    privkey = key.privKey.toWIF(network);
                }
                else {
                    privkey = "0x" + key.privKey.d.toString(16);
                    pubkey = "0x" + pubkey;
                }
                addAddressToList(index, address, pubkey, privkey);
            }, 50)
        }

        init();

    }

    function showMore() {
        let start = DOM.addresses.children().length;
        let rowsToAdd = parseInt(DOM.rowsToAdd.val());
        if (isNaN(rowsToAdd)) {
            rowsToAdd = 20;
            DOM.rowsToAdd.val("20");
        }
        if (rowsToAdd > 200) {
            let msg = "Generating " + rowsToAdd + " rows could take a while. ";
            msg += "Do you want to continue?";
            if (!confirm(msg)) {
                return;
            }
        }
        displayAddresses(start, rowsToAdd);
    }

    function clearDisplay() {
        clearAddressesList();
        clearKey();
        hideValidationError();
    }

    function clearAddressesList() {
        DOM.addresses.empty();
    }

    function clearKey() {
        DOM.rootKey.val("");
        DOM.extendedPrivKey.val("");
        DOM.extendedPubKey.val("");
    }

    function addAddressToList(index, address, pubkey, privkey) {
        let row = $(addressRowTemplate.html());
        // Elements
        let indexCell = row.find(".index span");
        let addressCell = row.find(".address a");
        let pubkeyCell = row.find(".pubkey a");
        let privkeyCell = row.find(".privkey a");
        // Content
        let indexText = derivationPath + "/" + index;
        indexCell.text(indexText);
        addressCell.text(address);
        addressCell.on("click", createQR);
        pubkeyCell.text(pubkey);
        pubkeyCell.on("click", createQR);
        privkeyCell.text(privkey);
        privkeyCell.on("click", createQR);
        // Visibility
        if (!showIndex) {
            indexCell.addClass("invisible");
        }
        if (!showAddress) {
            addressCell.addClass("invisible");
        }
        if (!showPubKey) {
            pubkeyCell.addClass("invisible");
        }
        if (!showPrivKey) {
            privkeyCell.addClass("invisible");
        }
        DOM.addresses.append(row);
    }
    function createQR(event) {
        let target = event.target;
        let address = target.innerText;
        let parent = target.parentNode;
        if ($("#" + address).length) {
            $("#" + address).remove()
        } else {
            let div = $("<div/>")

            div.attr("id", address);
            div.qrcode(address);
            div.appendTo(parent)
        }
    }
    function hasStrongRandom() {
        return 'crypto' in window && window['crypto'] !== null;
    }

    function disableForms() {
        $("form").on("submit", function (e) {
            e.preventDefault();
        });
    }

    function setBip44DerivationPath() {
        let purpose = parseIntNoNaN(DOM.bip44purpose.val(), 44);
        let coin = parseIntNoNaN(DOM.bip44coin.val(), 0);
        let account = parseIntNoNaN(DOM.bip44account.val(), 0);
        let change = parseIntNoNaN(DOM.bip44change.val(), 0);
        let path = "m/";
        path += purpose + "'/";
        path += coin + "'/";
        path += account + "'";
        if (!network.ethereum) {
            path += "/" + change;
        }
        DOM.bip44path.val(path);
        derivationPath = DOM.bip44path.val();
    }

    function parseIntNoNaN(val, defaultVal) {
        let v = parseInt(val);
        if (isNaN(v)) {
            return defaultVal;
        }
        return v;
    }

    function showPending() {
        DOM.feedback
            .text("Calculating...")
            .show();
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }



    function populateNetworkSelect() {
        networks = networks.sort(function (a, b) { return (a.name > b.name) ? 1 : ((b.name > a.name) ? -1 : 0); });

        for (let i = 0; i < networks.length; i++) {
            let network = networks[i];
            let option = $("<option>");
            option.attr("value", i);
            option.text(network.name);
            DOM.phraseNetwork.append(option);
        }
    }

    let networks = [

        {
            name: "Microbitcoin",
            onSelect: function () {
                network = bitcoin.networks.microbitcoin;
                DOM.bip44coin.val(0);
            },
        },
        {
            name: "Microbitcoin Testnet",
            onSelect: function () {
                network = bitcoin.networks.microbitcointest;
                DOM.bip44coin.val(0);
            },
        },
    ]

    init();

})();
