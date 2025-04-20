import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./public/temp");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Enhanced configuration for registration
export const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    // Explicitly allow only these fields
    if (['avatar', 'coverImage'].includes(file.fieldname)) {
      cb(null, true);
    } else {
      cb(new Error(`Unexpected field: ${file.fieldname}`), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB per file
    files: 2 // Max 2 files total
  }
});


