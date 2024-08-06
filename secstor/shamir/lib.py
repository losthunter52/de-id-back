from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
import io


class BaseSecretSharing:
    def __init__(self, n, k):
        self.n = n
        self.k = k

    @staticmethod
    def checkSecurity(n, k):
        if k < 2:
            raise Exception("Parameter 'k' has to be at least 2")

    @staticmethod
    def validateShareCount(n, k):
        return n >= k

    def determineMissingShares(self, shares):
        missing = set(range(1, self.n + 1))
        missing -= set(share.getId() for share in shares)
        return list(missing)

    def getN(self):
        return self.n

    def getK(self):
        return self.k

class GF256:
    GEN_POLY = 0x11D 

    LOG_TABLE = [0] * 256  
    ALOG_TABLE = [0] * 1025  

    @staticmethod
    def initialize_tables():
        GF256.LOG_TABLE[0] = 512
        GF256.ALOG_TABLE[0] = 1

        for i in range(1, 255):
            next_val = GF256.ALOG_TABLE[i - 1] * 2
            if next_val >= 256:
                next_val ^= GF256.GEN_POLY

            GF256.ALOG_TABLE[i] = next_val
            GF256.LOG_TABLE[GF256.ALOG_TABLE[i]] = i

        GF256.ALOG_TABLE[255] = GF256.ALOG_TABLE[0]
        GF256.LOG_TABLE[GF256.ALOG_TABLE[255]] = 255

        for i in range(256, 510):  
            GF256.ALOG_TABLE[i] = GF256.ALOG_TABLE[i % 255]

        GF256.ALOG_TABLE[510] = 1  

        for i in range(511, 1020):  
            GF256.ALOG_TABLE[i] = 0

    @staticmethod
    def add(a, b):
        return a ^ b

    @staticmethod
    def sub(a, b):
        return a ^ b 

    @staticmethod
    def mult(a, b):
        return GF256.ALOG_TABLE[GF256.LOG_TABLE[a] + GF256.LOG_TABLE[b]]

    @staticmethod
    def pow(a, p):
        if a == 0 and p != 0:
            return 0
        return GF256.ALOG_TABLE[p * GF256.LOG_TABLE[a] % 255]

    @staticmethod
    def inverse(a):
        return GF256.ALOG_TABLE[255 - (GF256.LOG_TABLE[a] % 255)]

    @staticmethod
    def div(a, b):
        if b == 0:
            raise ArithmeticError("Division by 0")

        return GF256.ALOG_TABLE[GF256.LOG_TABLE[a] + 255 - GF256.LOG_TABLE[b]]

    @staticmethod
    def evaluateAt(coeffs, x):
        degree = len(coeffs) - 1
        result = coeffs[degree]

        for i in range(degree - 1, -1, -1):
            result = GF256.add(GF256.mult(result, x), coeffs[i])

        return result

class GF256Matrix:
    def __init__(self, input_matrix):
        self.matrix = input_matrix

    def inverse(self):
        return self._inverse(True)

    def right_multiply(self, vec):
        if len(vec) != len(self.matrix) or len(vec) != len(self.matrix[0]):
            raise ArithmeticError("when matrix is MxN, vector must be Nx1")

        result = [0] * len(vec)
        for i in range(len(vec)):
            tmp = 0
            for j in range(len(vec)):
                tmp = GF256.add(tmp, GF256.mult(self.matrix[i][j], vec[j]))
            result[i] = tmp
        return result

    def right_multiply_into(self, result, vec):
        if len(vec) != len(self.matrix) or len(vec) != len(self.matrix[0]):
            raise ArithmeticError("when matrix is MxN, vector must be Nx1")

        for i in range(len(vec)):
            tmp = 0
            for j in range(len(vec)):
                tmp = GF256.add(tmp, GF256.mult(self.matrix[i][j], vec[j]))
            result[i] = tmp
        return result

    def _find_and_swap_non_zero_in_row(self, i, num_rows, tmp_matrix, inv_matrix, throw_exception):
        found = False

        for j in range(i + 1, num_rows):
            if tmp_matrix[j][i] != 0:
                tmp_matrix[i], tmp_matrix[j] = tmp_matrix[j], tmp_matrix[i]
                inv_matrix[i], inv_matrix[j] = inv_matrix[j], inv_matrix[i]
                found = True
                break

        if not found and throw_exception:
            raise RuntimeError("blub")

        return found

    def _inverse(self, throw_exception):
        num_rows = len(self.matrix)
        tmp_matrix = [row[:] for row in self.matrix]
        inv_matrix = [[0] * num_rows for _ in range(num_rows)]

        for i in range(num_rows):
            inv_matrix[i][i] = 1

        for i in range(num_rows):
            if tmp_matrix[i][i] == 0:
                found_non_zero = self._find_and_swap_non_zero_in_row(i, num_rows, tmp_matrix, inv_matrix, throw_exception)
                if not found_non_zero:
                    num_rows -= 1

            coef = tmp_matrix[i][i]
            inv_coef = GF256.inverse(coef)
            self._normalize_row(tmp_matrix[i], inv_matrix[i], inv_coef)

            for j in range(num_rows):
                if j != i:
                    coef = tmp_matrix[j][i]
                    if coef != 0:
                        self._mult_and_subtract(tmp_matrix[j], tmp_matrix[i], coef)
                        self._mult_and_subtract(inv_matrix[j], inv_matrix[i], coef)

        return GF256Matrix(inv_matrix)

    def _mult_and_subtract(self, row, normalized, coef):
        for i in range(len(row)):
            row[i] = GF256.sub(row[i], GF256.mult(normalized[i], coef))

    @staticmethod
    def _normalize_row(tmp_matrix, inv_matrix, element):
        for i in range(len(tmp_matrix)):
            tmp_matrix[i] = GF256.mult(tmp_matrix[i], element)
            inv_matrix[i] = GF256.mult(inv_matrix[i], element)

    def get_num_rows(self):
        return len(self.matrix)


class BCDigestRandomSource:
    def __init__(self, digest=None):
        self.digest = digest
        if digest is None:
            self.digest = 'SHA-1'

    def fillBytes(self, toBeFilled):
        toBeFilled[:] = get_random_bytes(len(toBeFilled))

    def fillBytesAsInts(self, toBeFilled):
        random_bytes = get_random_bytes(len(toBeFilled))
        for i in range(len(toBeFilled)):
            toBeFilled[i] = random_bytes[i]

    def __str__(self):
        return f"BCDigestRandomSource({self.digest})"


class ErasureDecoder():
    def __init__(self, xValues, k):
        self.k = k
        if all(x == 0 for x in xValues):
            raise ValueError("All xValues are zero. Please provide valid xValues.")
        
        matrixX = [[GF256.pow(xValues[i], j) for j in range(k)] for i in range(k)]
        self.matrix = GF256Matrix(matrixX).inverse()


    def decode(self, y, errorCount):
        if errorCount != 0:
            raise Exception("Erasuredecoder cannot fix errors")
        if len(self.matrix.matrix) != len(y):
            raise Exception("Different Lengths")
        if self.k > len(self.matrix.matrix):
            raise Exception("Seems to be a Configuration error")
        return self.matrix.right_multiply(y)

    def decodeUnsafe(self, target, y, errorCount):
        return self.matrix.right_multiply_into(target, y)

class ErasureDecoderFactory():
    def createDecoder(self, xValues, k):
        return ErasureDecoder(xValues, k)


class Share:
    VERSION = 5

    @staticmethod
    def writeMap(sout, map):
        sout.write(int.to_bytes(len(map), 4, 'big'))
        for key, value in map.items():
            sout.write(bytes([key]))
            value_bytes = value.encode('utf-8')  
            sout.write(int.to_bytes(len(value_bytes), 4, 'big'))
            sout.write(value_bytes)

    def __init__(self, id, x, y_values):
        self.id = id
        self.x = x
        self.y_values = y_values

    def getX(self):
        return self.x

    def getId(self):
        return self.id

    def getYValues(self):
        return self.y_values

    def getSerializedData(self):
        buffer = io.BytesIO()
        sout = io.DataOutputStream(buffer)
        self.writeMap(sout, {"archistar-share-type": self.getShareType(),
                             "archistar-version": str(self.VERSION),
                             "archistar-id": str(self.getId()),
                             "archistar-length": str(len(self.getYValues()))})
        return buffer.getvalue()

    def getCommonMetaData(self):
        return {"archistar-share-type": self.getShareType(),
                "archistar-version": str(self.VERSION),
                "archistar-id": str(self.getId()),
                "archistar-length": str(len(self.getYValues()))}

    def getMetaData(self):
        return {}

    def compareTo(self, t):
        try:
            if self.getSerializedData() == t.getSerializedData():
                return 0
            else:
                return t.getId() - self.getId()
        except IOError:
            return t.getId() - self.getId()

    def getShareType(self):
        return ""

    def getOriginalLength(self):
        return 0

class IndexKeyPair:
    def __init__(self, index, key):
        self.index = index
        self.key = key

    def __str__(self):
        return f"Index: {self.index}, Key: {self.key}"


class ShamirShare:
    def __init__(self, id, body):
        if id == 0:
            raise ValueError("X must not be 0")
        self.id = id
        self.body = body

    def getX(self):
        return self.id

    def getId(self):
        return self.id

    def getYValues(self):
        return self.body

    def getSerializedData(self):
        return self.body

    def getMetaData(self):
        return self.getCommonMetaData()

    def getShareType(self):
        return "SHAMIR"

    def getOriginalLength(self):
        return len(self.body)

    def __str__(self):
        return f"ShamirShare{{x={self.id}, body.length={len(self.body)}}}"

    def __eq__(self, o):
        if isinstance(o, ShamirShare):
            return self.id == o.id and self.body == o.body
        return False

    def __hash__(self):
        return hash((self.id, self.body))



class GeometricSecretSharing(BaseSecretSharing):
    def __init__(self, n, k, decoderFactory):
        super().__init__(n, k)
        self.decoderFactory = decoderFactory
        self.xValues = [i + 1 for i in range(n)]
        self.mulTables = [[GF256.mult(i + 1, j) for j in range(256)] for i in range(n)]

    @staticmethod
    def extractXVals(shares, k):
        return [share.getId() for share in shares[:k]]

    def share(self, data):
        if data is None:
            data = b''

        try:
            output = [bytearray(self.encodedSizeFor(len(data))) for _ in range(self.n)]
            self.share_impl(output, data)
            return self.createShares(self.xValues, output, len(data))
        except Exception as ex:
            raise Exception("impossible: share failed: " + str(ex))


    def createShares(self, xValues, results, originalLength):
        raise NotImplementedError

    def reconstruct(self, shares):
        if not self.validateShareCount(len(shares), self.k):
            raise Exception("Not enough shares to reconstruct")

        originalLength = shares[0].getOriginalLength()
        for s in shares:
            if s.getOriginalLength() != originalLength:
                raise Exception("Shares have different original length")

        xTmpValues = self.extractXVals(shares, self.k)
        yValues = [share.getYValues() for share in shares]
        return self.reconstruct_impl(yValues, xTmpValues, originalLength)

    def reconstructPartial(self, shares, start):
        return self.reconstruct(shares)

    def decodeData(self, encoded, originalLength, result, offset):
        raise NotImplementedError

    def encodedSizeFor(self, length):
        raise NotImplementedError

    def share_impl(self, output, data):
        raise NotImplementedError

    def reconstruct_impl(self, input, xValues, originalLength):
        decoder = self.decoderFactory.createDecoder(xValues, self.k)
        result = bytearray(originalLength)
        resultMatrix = [0] * self.k

        posResult = 0
        posInput = 0

        while posResult < originalLength:
            yValues = [(byte & 0xFF) for byte in input[posInput]]
            posInput += 1

            try:
                decoder.decodeUnsafe(resultMatrix, yValues, 0)
                posResult = self.decodeData(resultMatrix, originalLength, result, posResult)
            except Exception as e:
                raise Exception(str(e))

        return bytes(result)


class ShamirPSS(GeometricSecretSharing):
    def __init__(self, n, k, rng=BCDigestRandomSource(), decoderFactory=ErasureDecoderFactory()):
        super().__init__(n, k, decoderFactory)
        self.rng = rng
        self.rand = bytearray(k - 1)
        self.xValues = [i + 1 for i in range(n)]
        self.mulTables = [[GF256.mult(i + 1, j) for j in range(256)] for i in range(n)]

    def __str__(self):
        return f"ShamirPSS({self.n}/{self.k})"

    def decodeData(self, encoded, originalLength, result, offset):
        result[offset] = encoded[0] & 0xFF
        return offset + 1

    def createShares(self, xValues, results, originalLength):
        shares = []
        for i in range(self.n):
            shares.append(ShamirShare(xValues[i], results[i]))
        return shares

    def encodedSizeFor(self, length):
        return length

    def share_impl(self, output, data):
        try:
            for i in range(len(data)):
                self.rng.fillBytes(self.rand)
                for j in range(self.n):
                    res = self.rand[0] & 0xFF
                    for y in range(1, self.k - 1):  
                        res = GF256.add(self.rand[y] & 0xff, self.mulTables[j][res])
                    output[j][i] = GF256.add(data[i] & 0xff, self.mulTables[j][res])

        except Exception as ex:
            raise Exception("Failed to share data: " + str(ex)) 




    def reconstruct_impl(self, input, xValues, originalLength):
        decoder = self.decoderFactory.createDecoder(xValues, self.k)
        result = bytearray(originalLength)
        resultMatrix = [0] * self.k

        posResult = 0
        posInput = 0

        while posResult < originalLength:
            yValues = [input[j][posInput] & 0xff for j in range(self.k)]

            posInput += 1

            try:
                decoder.decodeUnsafe(resultMatrix, yValues, 0)
                posResult = self.decodeData(resultMatrix, originalLength, result, posResult)
            except Exception as e:
                raise Exception(str(e))

        return bytes(result)






class ReconstructionResult:
    def __init__(self, data=None, errors=None):
        self.data = data if data is not None else bytearray()
        self.okay = errors is None
        self.errors = errors if errors is not None else []

    def getData(self):
        return self.data

    def getTextData(self):
        if self.okay:
            return self.data
        else:
            error_msg = "\n".join(self.errors)
            raise Exception(f"Tried to read data from a failed reconstruction:\n{error_msg}")

    def isOkay(self):
        return self.okay

    def getErrors(self):
        return self.errors



class CryptoEngine:
    def share(self, data):
        raise NotImplementedError()

    def reconstruct(self, shares):
        raise NotImplementedError()

    def reconstructPartial(self, shares, start):
        raise NotImplementedError()

    def recover(self, shares):
        raise NotImplementedError()

    def getParams(self):
        raise NotImplementedError()


class ShamirEngine(CryptoEngine):
    def __init__(self, n, k, rng=BCDigestRandomSource()):
        self.n = n
        self.k = k
        self.output = []
        decoder_factory = ErasureDecoderFactory()
        self.engine = ShamirPSS(n, k, rng, decoder_factory)

    def share(self, data):
        return self.engine.share(data)
    
    def reconstruct(self, shares):
        try:
            return ReconstructionResult(self.engine.reconstruct(shares))
        except Exception as e:
            return ReconstructionResult([str(e)])

    def reconstructPartial(self, shares, start):
        try:
            return ReconstructionResult(self.engine.reconstructPartial(shares, start))
        except Exception as e:
            return ReconstructionResult([str(e)])

    def recover(self, shares):
        return self.engine.recover(shares)

    def getParams(self):
        return f"{self.n}-{self.k}"

    def __str__(self):
        return "Shamir"

class ArchistarEngine:
    def __init__(self, engine):
        self.engine = engine
        self.shares = None

    def split(self, data):
        self.shares = self.engine.share(data.encode('utf-8'))

    def reconstruct(self, keyNumber=None):
        if keyNumber is None:
            keyNumber = len(self.shares)
        kShares = self.shares[:keyNumber]
        result = self.engine.reconstruct(kShares)
        
        if result.isOkay():
            return result.getTextData()  
        else:
            error_msg = "\n".join(result.getErrors())
            raise Exception(f"Reconstruction failed:\n{error_msg}")

    def getEngine(self):
        return str(self.engine)

    def getAlgorithm(self):
        return str(self.engine)

    def getPieces(self):
        if self.shares is None:
            raise Exception("This engine was not used yet.")
        pieces = [IndexKeyPair(share.getX(), b64encode(share.getYValues()).decode('utf-8')) for share in self.shares]
        return pieces

    def setShares(self, shares):
        self.shares = shares



class EngineMaker:
    def __init__(self, n, k):
        self.shamir = ArchistarEngine(ShamirEngine(n, k))
        self.n = n
        self.k = k

    def split(self, data, algorithm):
        if algorithm.lower() == "shamir":
            self.shamir.split(data)
        else:
            raise Exception("Algorithm didn't match any of valid types")

    def reconstruct(self, algorithm, keyNumber=None):
        if algorithm.lower() == "shamir" and self.shamir.getPieces():
            result = self.shamir.reconstruct(keyNumber)
            if isinstance(result, list):
                return "\n".join(result)
            else:
                return result

        raise Exception("You need to split the shares in order to reconstruct them")

def shamir_split(n, k, data):
    GF256.initialize_tables()  

    engine_maker = EngineMaker(n, k)

    engine_maker.split(data, "shamir")

    shares = []

    for index_key_pair in engine_maker.shamir.getPieces():
       shares.append({
           "x": index_key_pair.index,
           "y": index_key_pair.key
       })

    secret_share = {
        "shares": shares
    }
    
    return secret_share

def shamir_reconstruct(n, k, secret_share): 
    GF256.initialize_tables()    

    engine_maker = EngineMaker(n, k)

    shares = []

    for share in secret_share["shares"]:
        shares.append(ShamirShare(
            share["x"], b64decode(share["y"])
        ))

    engine_maker.shamir.setShares(shares)

    secret = engine_maker.reconstruct("shamir", k).decode("utf-8")

    return secret
