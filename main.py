import viginereBreaker
import numpy
from spellchecker import SpellChecker
checker = SpellChecker()
cipherText = "Tk bzbs fmrow t fhec ugwey hw jmblqbeo ubpuxia ots qxmmdhprw. Yinbnt lfuw eoaz dmklatxj bztt fafcdw br xekjrpgxu, wfx kahna s kepbgm (sg ayzfzamhz) pyqua if t cqkm os lkmhl tb ivzxhrz yfz uaaazzvy ilnbebwqt yxkbwks vgkw ubpuxibwqt parzsvtrkj. Ql bs nejw fxcrljijr tb vywgle n lvkjxt xxp. Ql piye sm mleq mfowmhrk nqla tux jmdxcgxu idzoebkpe. Yoe xoieilr, mym segbkzbzf mnr sm s leamvvux mbov msvh yxkbwk rvzyb sgd gav awvrrm bmq fal uv i harnlv jq mhexv xgligbfvk. Mhvl uqkmiavkqgg cbfva xkoz mym hhsfbsqdbtl mf zwwupx kpw tmbneb gy iayfzettvhe bztt utmm lh br xokztntxu jwmwrxe qfmeexjbww pnkkqwl. Tux eceuee hw xgligbfvk hf uhn umvh nec twmtrkj azhuyw sm ehvrw za lae zhjb afpbkkifm iayfzettvhe qf mhvl jqlnagbfv, oaiyx kpw bnshiusmibg rjgnt gav nsvt garb lae faznl lhbncl tx prkwwjfeq mf bzx rvzyb al nbm tzmvine wwj feflrow'l srvlzamy ngu ksg br miiflmvmkmv tt gav jwziagzvy hf gav uwlsnzv eamhbnk mfvrlikqgg. Mbkvwnxr, fntp vbsgbeklboa tctgps gh law mhr tcogkigad umetvicm lbmrl nqla dvywmjxng dvgk, yoe xoieilr wlzagg phdumgiptkqgg wvmy layfrkvvl iebicm."
cipherTextBeforeSwitch = "At this stage a full model of building ciphers was developed. Having some long messages that should be encrypted, one knows a recipe (an algorithm) which is a list of steps to perform for changing plaintext letters into ciphertext characters. It is also necessary to choose a secret key. It will be used together with the selected algorithm. For example, the algorithm may be a sentence move each letter right and the secret key may be a phrase by three positions. This distinction comes from the possibility to reduce the amount of information that have to be exchanged between interested parties. The number of positions of how much all letters should be moved is the most important information in this situation, while the information about the fact that the shift should be performed to the right is not crucial for message's security and can be transmitted at the beginning of the message without encryption. Moreover, such distinction allows to use the algorithm multiple times with different keys, for example during communication with different people."
cipherText2 = "Vb trvv kcaqz i feyo exdog wf lhldmixb kizuhjb wkn lefrogyen. Civsaj kxmo gwnq zhkbaqza trnw kqoegl bo rquayzomd, yah cwogn i roplhn (ax vtgyellqm) gcqcr vv s uico wf cghhb ty kmrpbue oob xpaxtlfp pvvqndral uedomrc vqlx cskpebghpc crvzamghjb. Id da avfr fnconaabl wg lhyjae k fhuaed fmy. Sg zaul lz csoq wgpedcmr gvwz cho nmlopwwm avbwrsgke. Oob zfawcow, cho vtgyellqm wvg bo n vwwtoike wbyw namc tedghj aiqcb axq wzn soxzed xhq vai wm a zuusbe lt bhbrh hxssoqoxf. Wzrs ndatsaflrox xwmof ijxm dcm pyfvakivdby db uwmumz bho npgdnd jn ixsrjvaddwn dudl qafz bo lr hplhkioen ohlfeoi qndruwbtoy xabglwb. Trz vuwohj xf zjaidvrfb op cww whfz jlv gmtdruk bhyptd lr pgeen da trr pgbt shxobgdfc ixawrwnwaxn si bhsf vacukoqox, jkaue dcm ixsrjvaddwn kormc trz namg wzjt dcm srvil bhyptd lr swafymuen gr lqe bdohd vv fxt mmccsno xxr wzaskth'k bempzidl dfm cki je dedfbmsoben nw lqe lzoixalfp op ope wrvkjgo rqtrbxl nnmmgpdvrf. Vobzwvoe, vmlh ndatsaflrox vtlyjv lx ucz bho noyxrsopm wholrpvz biwrv ortr yqfpruwwt uzgs, pbu wgawkte nhuawg mjumealujtsjv wsgk vrfpzzexg swxpvz."
cutoffPercentage = 0.05

def removeSpecialChars(text):
    specialCharactersString = "0123456789./*-+~`!@#$%&*()_+-=[]\{}|;':,./<>?"
    outputText = ""
    for i in range(0,len(text),1):
        if (not (text[i] in specialCharactersString)):
            outputText = outputText + text[i]
    return outputText

def getPercentageSpelledRight(text):
    textNoSpecial = removeSpecialChars(text)
    wordArray = textNoSpecial.split()
    misspellings = 0
    wordCount = 0
    for word in wordArray:
        wordCount = wordCount + 1
        if not(word in checker):
            misspellings = misspellings + 1
        percentage = (misspellings / wordCount)
    return percentage

viginereOutput = viginereBreaker.viginereBreaker(cipherText2)
viginerePercentage = getPercentageSpelledRight(viginereOutput)

if(viginerePercentage < cutoffPercentage):
    print("This was encoded using Viginere Cipher")
    print("Here is the original text")
    print(viginereOutput)