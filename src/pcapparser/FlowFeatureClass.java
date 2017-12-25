package pcapparser;

/**
 * Flow class for classify
 *
 * @author lipeng
 * @version 0.1
 */
public enum FlowFeatureClass {
    DEFAULT,
    BULK,
    INTERACTIVE,
    STREAMING,
    TRANSACTION;

    public static FlowFeatureClass ofClass(int app) {
        switch (app) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 11:
            case 16:
            case 21:
            case 23:
            case 29:
            case 48:
            case 51:
            case 64:
            case 65:
            case 67:
            case 68:
            case 69:
            case 77:
            case 91:
            case 92:
            case 93:
            case 118:
            case 112:
            case 113:
            case 130:
            case 131:
            case 159:
            case 161:
            case 185:
            case 193:
                return INTERACTIVE;
            case 7:
            case 22:
            case 30:
            case 33:
            case 34:
            case 35:
            case 36:
            case 37:
            case 60:
            case 62:
            case 63:
            case 96:
            case 97:
            case 98:
            case 121:
            case 136:
            case 137:
            case 138:
            case 143:
            case 147:
            case 169:
            case 175:
            case 203:
            case 217:
            case 221:
            case 224:
            case 226:
            case 228:
            case 231:
                return BULK;
            case 5:
            case 19:
            case 20:
            case 50:
            case 111:
            case 114:
            case 150:
            case 167:
            case 170:
            case 179:
            case 182:
            case 225:
                return TRANSACTION;
            case 39:
            case 40:
            case 41:
            case 42:
            case 43:
            case 44:
            case 45:
            case 46:
            case 47:
            case 52:
            case 53:
            case 54:
            case 56:
            case 57:
            case 58:
            case 59:
            case 61:
            case 71:
            case 72:
            case 74:
            case 75:
            case 76:
            case 84:
            case 87:
            case 88:
            case 89:
            case 90:
            case 94:
            case 95:
            case 104:
            case 105:
            case 106:
            case 107:
            case 108:
            case 109:
            case 116:
            case 117:
            case 124:
            case 125:
            case 132:
            case 133:
            case 134:
            case 139:
            case 141:
            case 142:
            case 144:
            case 145:
            case 148:
            case 156:
            case 157:
            case 158:
            case 181:
            case 183:
            case 189:
            case 194:
            case 196:
            case 219:
            case 234:
                return STREAMING;
            default:
                return DEFAULT;
        }
    }

    @Override
    public String toString() {
        return super.toString();
    }
}