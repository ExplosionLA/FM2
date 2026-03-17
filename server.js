// ====== 1. 引入必要模組 ======
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// ====== 2. 建立 Express 應用 ======
const app = express();
app.use(cors());
app.use(express.json()); // 解析 JSON 請求主體
app.use(express.urlencoded({ extended: true }));

// ====== 3. 連接 Supabase ======
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ====== 4. 設定 JWT 密鑰 ======
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key';
const JWT_EXPIRES_IN = '7d';

// ====== 5. Middleware: 驗證 Token ======
// 這個函式會掛在需要保護的路由前面，用來確認使用者是否已登入
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Token 格式通常是: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '請先登入' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token 無效或過期，請重新登入' });
    }
    // 驗證成功，將使用者資訊存入 req.user，方便後面的路由使用
    req.user = user;
    next();
  });
};

// ====== 6. 基礎路由 ======
app.get('/', (req, res) => {
  res.json({ message: '✅ 親師生互動系統 API 運行中！', version: '2.0.0' });
});

// ====== 7. 認證相關 API (註冊與登入) ======

// 7.1 註冊 API
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: '請填寫完整資料' });
    }

    // 檢查重複 (使用 maybeSingle 避免報錯)
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .or(`username.eq.${username},email.eq.${email}`)
      .maybeSingle();

    if (existingUser) {
      return res.status(409).json({ error: '帳號或 Email 已被註冊' });
    }

    // 加密密碼
    const passwordHash = await bcrypt.hash(password, 10);

    // 寫入資料庫
    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert({
        username,
        email,
        password_hash: passwordHash,
        role: role || 'student', // 預設為學生
        is_verified: true
      })
      .select()
      .single();

    if (insertError) throw insertError;

    // 註冊成功直接給 Token
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username, role: newUser.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: '註冊成功',
      token,
      user: { id: newUser.id, username: newUser.username, role: newUser.role }
    });

  } catch (error) {
    console.error('註冊錯誤:', error);
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// 7.2 登入 API
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 查詢使用者
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .or(`username.eq.${username},email.eq.${username}`)
      .maybeSingle();

    if (error) {
        console.error('登入查詢錯誤:', error);
        return res.status(500).json({ error: '資料庫錯誤' });
    }

    // 驗證密碼
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: '帳號或密碼錯誤' });
    }

    // 生成 Token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      message: '登入成功',
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });

  } catch (error) {
    console.error('登入錯誤:', error);
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// ====== 8. 功能 API (需 Token 驗證) ======

// 8.1 提交功課 (僅限學生)
app.post('/api/homework', authenticateToken, async (req, res) => {
  try {
    // 檢查身分
    if (req.user.role !== 'student') {
      return res.status(403).json({ error: '只有學生可以提交功課' });
    }

    const { title, content } = req.body;
    if (!title || !content) {
      return res.status(400).json({ error: '標題與內容不能為空' });
    }

    // 寫入 homeworks 表
    const { error } = await supabase
      .from('homeworks')
      .insert({
        student_id: req.user.userId, // 從 Token 取得 ID
        student_name: req.user.username, // 從 Token 取得名稱
        title,
        content,
        status: 'pending'
      });

    if (error) throw error;

    res.json({ message: '功課提交成功！' });

  } catch (error) {
    console.error('提交功課錯誤:', error);
    res.status(500).json({ error: '提交失敗: ' + error.message });
  }
});

// 8.2 取得功課列表 (依角色不同回傳不同資料)
app.get('/api/homework', authenticateToken, async (req, res) => {
  try {
    const { userId, role } = req.user;
    
    // 預設查詢：按時間倒序
    let query = supabase
      .from('homeworks')
      .select('*')
      .order('created_at', { ascending: false });

    // === 邏輯分歧 ===
    if (role === 'student') {
      // 學生：只能看自己的
      query = query.eq('student_id', userId);

    } else if (role === 'teacher') {
      // 老師：看全部 (不需要額外過濾條件)
      // Pass (do nothing to query)

    } else if (role === 'parent') {
      // 家長：複雜邏輯
      // 1. 先去 parent_child 表找這個家長綁定了哪些孩子
      const { data: relations, error: relError } = await supabase
        .from('parent_child')
        .select('child_id')
        .eq('parent_id', userId);

      if (relError) throw relError;

      // 如果沒綁定任何孩子，直接回傳空陣列
      if (!relations || relations.length === 0) {
        return res.json([]); 
      }

      // 取出所有孩子的 ID，例如: [10, 15, 22]
      const childIds = relations.map(r => r.child_id);

      // 2. 查詢 homeworks，條件是 student_id 包含在 childIds 裡面
      query = query.in('student_id', childIds);
    }

    // 執行查詢
    const { data: homeworks, error } = await query;

    if (error) throw error;
    res.json(homeworks);

  } catch (error) {
    console.error('取得功課錯誤:', error);
    res.status(500).json({ error: '無法取得資料' });
  }
});

// 8.3 家長綁定學生 (僅限家長)
app.post('/api/bind-child', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'parent') {
      return res.status(403).json({ error: '只有家長可以使用此功能' });
    }

    const { childUsername } = req.body;
    if (!childUsername) {
      return res.status(400).json({ error: '請輸入學生帳號' });
    }

    // 步驟 A: 搜尋該學生是否存在
    const { data: child, error: findError } = await supabase
      .from('users')
      .select('id, role')
      .eq('username', childUsername)
      .maybeSingle();

    if (findError) throw findError;

    if (!child) {
      return res.status(404).json({ error: '找不到該帳號' });
    }

    if (child.role !== 'student') {
      return res.status(400).json({ error: '該帳號不是學生身分，無法綁定' });
    }

    // 步驟 B: 建立關聯
    const { error: bindError } = await supabase
      .from('parent_child')
      .insert({
        parent_id: req.user.userId,
        child_id: child.id
      });

    if (bindError) {
      // 錯誤代碼 23505 代表違反唯一約束 (已經綁定過了)
      if (bindError.code === '23505') {
        return res.status(409).json({ error: '您已經綁定過此學生了' });
      }
      throw bindError;
    }

    res.json({ message: `成功綁定學生：${childUsername}` });

  } catch (error) {
    console.error('綁定錯誤:', error);
    res.status(500).json({ error: '綁定失敗，請稍後再試' });
  }
});
// 8.4 取得個人中心資訊 (Profile & Stats) - 真實數據版
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { userId, role, username } = req.user;
    
    // 1. 取得使用者的詳細資料
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('email, role') 
      .eq('id', userId)
      .single();

    if (userError) throw userError;

    // 定義當前月份的第一天和最後一天 (用來計算本月數據)
    const date = new Date();
    const firstDay = new Date(date.getFullYear(), date.getMonth(), 1).toISOString().split('T')[0];
    const lastDay = new Date(date.getFullYear(), date.getMonth() + 1, 0).toISOString().split('T')[0];
    const today = date.toISOString().split('T')[0];

    // 初始化統計數據
    let stats = {
      pendingClasses: 0,
      completedClasses: 0,
      leaveCount: 0,
      absenceCount: 0
    };

    // 2. 只有學生或家長需要計算上課數據 (這裡先以學生邏輯為主)
    if (role === 'student') {
      
      // A. 計算「本月待上課」
      // 邏輯：找出該學生有報名的班級，並且在排課表中日期是大於等於今天，且在月底之前的課
      const { data: enrolledClasses } = await supabase
        .from('student_classes')
        .select('class_id')
        .eq('student_id', userId);
        
      if (enrolledClasses && enrolledClasses.length > 0) {
        const classIds = enrolledClasses.map(c => c.class_id);
        
        const { count: pendingCount } = await supabase
          .from('class_schedules')
          .select('*', { count: 'exact', head: true })
          .in('class_id', classIds)
          .gte('class_date', today)
          .lte('class_date', lastDay)
          .eq('status', '待點名');
          
        stats.pendingClasses = pendingCount || 0;
      }

      // B. 計算「本月已上課」(到課)
      const { count: completedCount } = await supabase
        .from('attendance')
        .select('*', { count: 'exact', head: true })
        .eq('student_id', userId)
        .eq('status', '到課')
        .gte('created_at', firstDay + 'T00:00:00Z'); // 本月
      stats.completedClasses = completedCount || 0;

      // C. 計算「請假」次數 (通常算累計或本月，這裡算累計)
      const { count: leaveCount } = await supabase
        .from('attendance')
        .select('*', { count: 'exact', head: true })
        .eq('student_id', userId)
        .eq('status', '請假');
      stats.leaveCount = leaveCount || 0;

      // D. 計算「缺勤」次數
      const { count: absenceCount } = await supabase
        .from('attendance')
        .select('*', { count: 'exact', head: true })
        .eq('student_id', userId)
        .eq('status', '缺勤');
      stats.absenceCount = absenceCount || 0;
    }

    // 3. 回傳整合後的資料給前端
    res.json({
      user: {
        id: userId,
        username: username,
        role: userData.role,
        email: userData.email,
        phone: '18888888888', // 如果 users 表加了 phone 欄位，可改為 userData.phone
      },
      stats: stats
    });

  } catch (error) {
    console.error('取得個人資訊錯誤:', error);
    res.status(500).json({ error: '無法取得個人資訊' });
  }
});

// ====== 9. 啟動伺服器 ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('========================================');
  console.log(`🚀 伺服器已啟動: http://localhost:${PORT}`);
  console.log('========================================');
});

module.exports = app;
