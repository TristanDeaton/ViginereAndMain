import numpy as np
TcipherTextUpper = "Tk bzbs fmrow t fhec ugwey hw jmblqbeo ubpuxia ots qxmmdhprw. Yinbnt lfuw eoaz dmklatxj bztt fafcdw br xekjrpgxu, wfx kahna s kepbgm (sg ayzfzamhz) pyqua if t cqkm os lkmhl tb ivzxhrz yfz uaaazzvy ilnbebwqt yxkbwks vgkw ubpuxibwqt parzsvtrkj. Ql bs nejw fxcrljijr tb vywgle n lvkjxt xxp. Ql piye sm mleq mfowmhrk nqla tux jmdxcgxu idzoebkpe. Yoe xoieilr, mym segbkzbzf mnr sm s leamvvux mbov msvh yxkbwk rvzyb sgd gav awvrrm bmq fal uv i harnlv jq mhexv xgligbfvk. Mhvl uqkmiavkqgg cbfva xkoz mym hhsfbsqdbtl mf zwwupx kpw tmbneb gy iayfzettvhe bztt utmm lh br xokztntxu jwmwrxe qfmeexjbww pnkkqwl. Tux eceuee hw xgligbfvk hf uhn umvh nec twmtrkj azhuyw sm ehvrw za lae zhjb afpbkkifm iayfzettvhe qf mhvl jqlnagbfv, oaiyx kpw bnshiusmibg rjgnt gav nsvt garb lae faznl lhbncl tx prkwwjfeq mf bzx rvzyb al nbm tzmvine wwj feflrow'l srvlzamy ngu ksg br miiflmvmkmv tt gav jwziagzvy hf gav uwlsnzv eamhbnk mfvrlikqgg. Mbkvwnxr, fntp vbsgbeklboa tctgps gh law mhr tcogkigad umetvicm lbmrl nqla dvywmjxng dvgk, yoe xoieilr wlzagg phdumgiptkqgg wvmy layfrkvvl iebicm."
TcipherTextBeforeSwitch = "At this stage a full model of building ciphers was developed. Having some long messages that should be encrypted, one knows a recipe (an algorithm) which is a list of steps to perform for changing plaintext letters into ciphertext characters. It is also necessary to choose a secret key. It will be used together with the selected algorithm. For example, the algorithm may be a sentence move each letter right and the secret key may be a phrase by three positions. This distinction comes from the possibility to reduce the amount of information that have to be exchanged between interested parties. The number of positions of how much all letters should be moved is the most important information in this situation, while the information about the fact that the shift should be performed to the right is not crucial for message's security and can be transmitted at the beginning of the message without encryption. Moreover, such distinction allows to use the algorithm multiple times with different keys, for example during communication with different people."
TkeyBefore = "tristan"
TkeyMode = "repeat"
alphabet = "abcdefghijklmnopqrstuvwxyz"
specialCharactersString = "0123456789 ./*-+~`!@#$%&*()_+-=[]\{}|;':,./<>?"
frequencyInEnglishValues = [0.0817, 0.0149, 0.0278, 0.0425, 0.127, 0.0223, 0.0202, 0.0609, 0.07, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.007]
indexOfCoincidenceEnglish = 0.067
maxPeriodNumber = 25

def seperateSpecialCharacters(cipherText):
    cipherText = cipherText.lower()
    lengthOfText = len(cipherText)
    cipherTextNoSpecialCharacters = ""
    cipherTextOnlySpecialCharacters = ""
    for i in range(0,lengthOfText,1):
        if (cipherText[i] in specialCharactersString):
            cipherTextOnlySpecialCharacters = cipherTextOnlySpecialCharacters + cipherText[i]
        else:
            cipherTextNoSpecialCharacters = cipherTextNoSpecialCharacters + cipherText[i]
            cipherTextOnlySpecialCharacters = cipherTextOnlySpecialCharacters + "^"
    return cipherTextOnlySpecialCharacters, cipherTextNoSpecialCharacters

def findPeriod(cipherTextNoSpecialCharacters):
    arrayOfAverageIC = np.zeros(maxPeriodNumber - 1)
    lengthOfTextNoSpecial = len(cipherTextNoSpecialCharacters)
    for period in range(1,maxPeriodNumber,1):
        #print("Period for this run is: " + str(period))
        averageIndexOfCoincidence = 0
        sequences = ["" for x in range(period)]
        for x in range(0,lengthOfTextNoSpecial,1):
            sequences[x%period] = sequences[x%period] + cipherTextNoSpecialCharacters[x]
        for sequenceNumber in range(0,period,1):
            indexOfCoincidence = 0
            lengthOfSequence = len(sequences[sequenceNumber])
            formulaP1Sequences = 1/(lengthOfSequence * (lengthOfSequence - 1))
            sumTotalIC = 0
            for c in alphabet:
                numberOfInstances = sequences[sequenceNumber].count(c)
                sumTotalIC = sumTotalIC + (numberOfInstances * (numberOfInstances - 1))
            indexOfCoincidence = sumTotalIC * formulaP1Sequences
            averageIndexOfCoincidence = averageIndexOfCoincidence + indexOfCoincidence
        averageIndexOfCoincidence = averageIndexOfCoincidence / period
        arrayOfAverageIC[period - 1] = averageIndexOfCoincidence
        #print("AverageIndexOfCoincidence: " + str(averageIndexOfCoincidence))
        #print("--------------------")
        periodValue = int(np.where(arrayOfAverageIC == arrayOfAverageIC.max())[0] + 1)
    return periodValue

def getFinalSequences(periodValue, cipherTextNoSpecialCharacters):
    lengthOfTextNoSpecial = len(cipherTextNoSpecialCharacters)
    finalSequences = ["" for x in range(periodValue)]
    for x in range(0,lengthOfTextNoSpecial,1):
        finalSequences[x%periodValue] = finalSequences[x%periodValue] + cipherTextNoSpecialCharacters[x]
    return finalSequences

def breakCaesar(finalSequences, sequenceNumber):
    #print(finalSequences[sequenceNumber])
    #shouldBe = TkeyBefore[sequenceNumber]
    totalChiValues = np.zeros(26)
    for caesarCipherInteger in range(0, len(alphabet), 1):
        #print("Letter: " + str(alphabet[caesarCipherInteger]) + " shouldBE: " + shouldBe + "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
        totalChiValue = 0
        potentialDecodedSequence = ""
        for j in range(0, len(finalSequences[sequenceNumber]), 1):
            tempIndex = (alphabet.index(finalSequences[sequenceNumber][j]) - caesarCipherInteger) % 26
            potentialDecodedSequence = potentialDecodedSequence + alphabet[tempIndex] 
        #print(potentialDecodedSequence)
        for c in range(0,len(alphabet),1):
            numberOfInstances = potentialDecodedSequence.count(alphabet[c])
            expectedNumberOfInstances = len(potentialDecodedSequence) * frequencyInEnglishValues[c]
            dif = numberOfInstances - expectedNumberOfInstances
            chiValue = pow(dif,2) / expectedNumberOfInstances
            totalChiValue = totalChiValue + chiValue
        #print(totalChiValue)
        totalChiValues[caesarCipherInteger] = totalChiValue
    return totalChiValues

def decodeCipher(finalSequences, arrayOfKeyBreakers, sequenceNumber):
    decodedSequence = ""
    for j in range(0, len(finalSequences[sequenceNumber]), 1):
        tempIndex = (alphabet.index(finalSequences[sequenceNumber][j]) - int(arrayOfKeyBreakers[sequenceNumber])) % 26
        decodedSequence = decodedSequence + alphabet[tempIndex]
    return decodedSequence

def combine(decodedSequences, periodValue, cipherTextNoSpecialCharacters):
    decoded = ""
    for i in range(0, len(cipherTextNoSpecialCharacters), 1):
        mod = i % periodValue
        div = i // periodValue
        decoded = decoded + decodedSequences[mod][div]
    return decoded

def addSpecialChars(decrypted, cipherTextOnlySpecialCharacters):
    normalText = ""
    counter = 0
    for i in range(0, len(cipherTextOnlySpecialCharacters), 1):
        if(cipherTextOnlySpecialCharacters[i] in specialCharactersString):
            normalText = normalText + cipherTextOnlySpecialCharacters[i]
        else:
            normalText = normalText + decrypted[counter]
            counter = counter + 1
    return normalText

def viginereBreaker(cipherTextUpper):
    cipherTextOnlySpecialCharacters, cipherTextNoSpecialCharacters = seperateSpecialCharacters(cipherTextUpper)
    periodValue = findPeriod(cipherTextNoSpecialCharacters)
    #print("Period of Cipher is: " + str(periodValue))
    finalSequences = getFinalSequences(periodValue, cipherTextNoSpecialCharacters)
    arrayOfKeyBreakers = np.zeros(periodValue)
    for sequenceNumber in range(0,periodValue,1):
        #print("\n\n\n\n\n")
        chiValues = breakCaesar(finalSequences, sequenceNumber)
        lowestChiValueIndex = int(np.where(chiValues == chiValues.min())[0])
        #print(alphabet[lowestChiValueIndex] + " has the lowest chi value")
        arrayOfKeyBreakers[sequenceNumber] = lowestChiValueIndex
    decodedSequences = ["" for x in range(periodValue)]
    key = ""
    output = ""
    for sequenceNumber in range(0,periodValue,1):
        decodedSequences[sequenceNumber] = decodeCipher(finalSequences, arrayOfKeyBreakers, sequenceNumber)
        key = key + alphabet[int(arrayOfKeyBreakers[sequenceNumber])]
    decrypted = combine(decodedSequences, periodValue, cipherTextNoSpecialCharacters)
    normalText = addSpecialChars(decrypted, cipherTextOnlySpecialCharacters)
    return normalText