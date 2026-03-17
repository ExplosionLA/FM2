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

// 8.5 取得當日課表 (Timetable)
app.get('/api/schedules', authenticateToken, async (req, res) => {
  try {
    const { userId, role } = req.user;
    // 如果前端有傳日期就用前端的，沒有就預設今天
    const targetDate = req.query.date || new Date().toISOString().split('T')[0];

    // 1. 準備查詢：從 class_schedules 表關聯 classes 表
    // 注意：Supabase 的 Join 語法是透過 Foreign Key 自動關聯的
    let query = supabase
      .from('class_schedules')
      .select(`
        id,
        class_date,
        start_time,
        end_time,
        status,
        classes (
          id,
          name,
          teacher_id
        )
      `)
      .eq('class_date', targetDate)
      .order('start_time', { ascending: true });

    // 2. 根據角色過濾資料
    if (role === 'teacher') {
      // 老師：只看自己教的課 (這裡因為 Supabase 限制，我們全抓出來在 Node 裡過濾比較保險)
      const { data: schedules, error } = await query;
      if (error) throw error;
      
      const teacherSchedules = schedules.filter(s => s.classes && s.classes.teacher_id == userId);
      return res.json(teacherSchedules);

    } else if (role === 'student') {
      // 學生：先找出他報名了哪些班級
      const { data: enrolled } = await supabase
        .from('student_classes')
        .select('class_id')
        .eq('student_id', userId);
        
      const classIds = enrolled ? enrolled.map(e => e.class_id) : [];
      
      if (classIds.length === 0) return res.json([]); // 沒報名任何班級
      
      // 再找出這些班級今天的排課
      const { data: studentSchedules, error } = await query.in('class_id', classIds);
      if (error) throw error;
      
      return res.json(studentSchedules);
    } else {
      // 其他角色 (家長/管理員) 暫時回傳空陣列或全部
      const { data: allSchedules, error } = await query;
      if (error) throw error;
      return res.json(allSchedules);
    }

  } catch (error) {
    console.error('取得課表錯誤:', error);
    res.status(500).json({ error: '無法取得課表資料' });
  }
});
// 8.5.1 取得當月有課的日期 (月曆視圖用)
app.get('/api/schedules/month', authenticateToken, async (req, res) => {
  try {
    const { userId, role } = req.user;
    const targetMonth = req.query.month; // 格式預期為 'YYYY-MM' (例如 '2024-12')
    
    // 計算該月的第一天與最後一天
    const startDate = `${targetMonth}-01`;
    const lastDay = new Date(targetMonth.split('-')[0], targetMonth.split('-')[1], 0).getDate();
    const endDate = `${targetMonth}-${lastDay}`;

    let query = supabase
      .from('class_schedules')
      .select('class_date, class_id, classes(teacher_id)')
      .gte('class_date', startDate)
      .lte('class_date', endDate);

    let schedules = [];

    // 根據角色過濾資料
    if (role === 'teacher') {
      const { data, error } = await query;
      if (error) throw error;
      schedules = data.filter(s => s.classes && s.classes.teacher_id == userId);
    } else if (role === 'student') {
      const { data: enrolled } = await supabase.from('student_classes').select('class_id').eq('student_id', userId);
      const classIds = enrolled ? enrolled.map(e => e.class_id) : [];
      if (classIds.length === 0) return res.json([]);
      
      const { data, error } = await query.in('class_id', classIds);
      if (error) throw error;
      schedules = data;
    }

    // 提取日期並去除重複
    const datesWithClasses = [...new Set(schedules.map(item => item.class_date))];
    res.json(datesWithClasses);

  } catch (error) {
    console.error('取得月曆資料錯誤:', error);
    res.status(500).json({ error: '無法取得月曆資料' });
  }
});
// 8.6 取得特定排課的點名名單與資訊
app.get('/api/rollcall/:scheduleId', authenticateToken, async (req, res) => {
  try {
    const { scheduleId } = req.params;

    // 1. 取得這堂課的基本資訊
    const { data: schedule, error: scheduleError } = await supabase
      .from('class_schedules')
      .select(`
        id, class_date, start_time, end_time, status,
        classes ( id, name )
      `)
      .eq('id', scheduleId)
      .single();
    if (scheduleError) throw scheduleError;

    // 2. 取得這個班級的報名學生名單與他們的剩餘課時
    const { data: students, error: studentsError } = await supabase
      .from('student_classes')
      .select(`
        student_id,
        remaining_credits,
        users ( id, username )
      `)
      .eq('class_id', schedule.classes.id);
    if (studentsError) throw studentsError;

    // 3. 取得這堂課"已經點過"的紀錄 (如果有的話)
    const { data: attendances, error: attError } = await supabase
      .from('attendance')
      .select('*')
      .eq('schedule_id', scheduleId);
    if (attError) throw attError;

    // 4. 將資料整合成前端好用的格式
    const studentList = students.map(st => {
      const record = attendances.find(a => a.student_id === st.student_id);
      return {
        student_id: st.student_id,
        username: st.users ? st.users.username : '未知學生',
        remaining_credits: st.remaining_credits,
        status: record ? record.status : '到課', // 預設「到課」
        deduct_credits: record ? record.deduct_credits : 1.0 // 預設扣 1 課時
      };
    });

    res.json({
      schedule: schedule,
      students: studentList
    });

  } catch (error) {
    console.error('取得點名資訊錯誤:', error);
    res.status(500).json({ error: '無法取得點名資訊' });
  }
});

// 8.7 老師送出確認點名
app.post('/api/attendance', authenticateToken, async (req, res) => {
  try {
    const { scheduleId, classId, attendanceData } = req.body;
    // attendanceData 格式預期為: [{ student_id, status, deduct_credits }, ...]

    // 針對每個學生進行點名紀錄寫入與扣除課時
    for (const record of attendanceData) {
      // 1. 寫入或更新 attendance 表 (這裡用 upsert 來避免重複點名錯誤)
      // 注意：Supabase upsert 需要有 unique constraint (我們之前有設 UNIQUE(schedule_id, student_id))
      const { error: attError } = await supabase
        .from('attendance')
        .upsert({
          schedule_id: scheduleId,
          student_id: record.student_id,
          status: record.status,
          deduct_credits: record.deduct_credits
        }, { onConflict: 'schedule_id, student_id' });
      
      if (attError) console.error('點名寫入失敗:', attError);

      // 2. 如果狀態是「到課」，則從 student_classes 扣除剩餘課時
      // (實務上請假或缺勤要不要扣課時，可依你們的商業邏輯調整，這裡先示範到課才扣)
      if (record.status === '到課') {
        // 先取得目前的剩餘課時
        const { data: scData } = await supabase
          .from('student_classes')
          .select('remaining_credits')
          .eq('student_id', record.student_id)
          .eq('class_id', classId)
          .single();
          
        if (scData) {
          const newCredits = Math.max(0, scData.remaining_credits - record.deduct_credits);
          await supabase
            .from('student_classes')
            .update({ remaining_credits: newCredits })
            .eq('student_id', record.student_id)
            .eq('class_id', classId);
        }
      }
    }

    // 3. 更新排課表狀態為「已點名」
    await supabase
      .from('class_schedules')
      .update({ status: '已點名' })
      .eq('id', scheduleId);

    res.json({ message: '點名成功！' });

  } catch (error) {
    console.error('點名送出錯誤:', error);
    res.status(500).json({ error: '點名處理失敗' });
  }
});

// 8.8 取得老師負責的班級清單 (排課下拉選單用)
app.get('/api/teacher/classes', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'teacher') {
      return res.status(403).json({ error: '只有老師可以取得班級清單' });
    }

    const { data: classes, error } = await supabase
      .from('classes')
      .select('id, name')
      .eq('teacher_id', req.user.userId);

    if (error) throw error;
    res.json(classes);

  } catch (error) {
    console.error('取得班級清單錯誤:', error);
    res.status(500).json({ error: '無法取得班級資料' });
  }
});

// 8.9 批次新增排課紀錄
app.post('/api/schedules', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'teacher') {
      return res.status(403).json({ error: '只有老師可以排課' });
    }

    // 前端會把計算好的「多天」排課陣列傳過來
    // schedules 格式: [{ class_id, class_date, start_time, end_time, status: '待點名' }, ...]
    const { schedules } = req.body;

    if (!schedules || schedules.length === 0) {
      return res.status(400).json({ error: '排課資料不能為空' });
    }

    // 寫入資料庫
    const { error } = await supabase
      .from('class_schedules')
      .insert(schedules);

    if (error) throw error;

    res.json({ message: `成功新增 ${schedules.length} 堂課！` });

  } catch (error) {
    console.error('新增排課錯誤:', error);
    res.status(500).json({ error: '排課失敗，請稍後再試' });
  }
});
// ====== 請假系統 API ======

// 1. 家長送出請假申請
app.post('/api/leave', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'parent') {
      return res.status(403).json({ error: '只有家長可以提交請假申請' });
    }

    const { studentId, scheduleId, reason } = req.body;
    if (!studentId || !scheduleId || !reason) {
      return res.status(400).json({ error: '請提供完整的請假資訊' });
    }

    // 檢查該堂課是否已經請過假了
    const { data: existing, error: checkError } = await supabase
      .from('leave_requests')
      .select('id')
      .eq('student_id', studentId)
      .eq('schedule_id', scheduleId)
      .maybeSingle();
      
    if (existing) {
      return res.status(400).json({ error: '這堂課已經提交過請假申請了' });
    }

    // 寫入請假單
    const { error } = await supabase
      .from('leave_requests')
      .insert({
        parent_id: req.user.userId,
        student_id: studentId,
        schedule_id: scheduleId,
        reason: reason,
        status: '待審核'
      });

    if (error) throw error;
    res.json({ message: '請假申請已送出，請等候老師審核！' });

  } catch (error) {
    console.error('請假申請錯誤:', error);
    res.status(500).json({ error: '系統錯誤，請稍後再試' });
  }
});

// 2. 取得請假單列表 (老師看自己班級的，家長看自己小孩的)
app.get('/api/leave', authenticateToken, async (req, res) => {
  try {
    const { userId, role } = req.user;
    
    // 關聯查詢：抓出學生名字、課程名稱、上課時間
    let query = supabase
      .from('leave_requests')
      .select(`
        id, reason, status, created_at,
        student:users!student_id ( id, username ),
        schedule:class_schedules ( id, class_date, start_time, end_time, classes(name, teacher_id) )
      `)
      .order('created_at', { ascending: false });

    if (role === 'parent') {
      // 家長只看自己送出的
      query = query.eq('parent_id', userId);
    } 
    
    const { data: requests, error } = await query;
    if (error) throw error;

    if (role === 'teacher') {
      // 老師只看自己負責的班級的請假單
      const teacherRequests = requests.filter(r => r.schedule.classes.teacher_id == userId);
      return res.json(teacherRequests);
    }

    res.json(requests);

  } catch (error) {
    console.error('取得請假單錯誤:', error);
    res.status(500).json({ error: '無法取得請假紀錄' });
  }
});

// 3. 老師審核請假單 (批准或拒絕)
app.put('/api/leave/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'teacher') {
      return res.status(403).json({ error: '只有老師可以審核請假' });
    }

    const { id } = req.params;
    const { status } = req.body; // '已批准' 或 '已拒絕'

    if (!['已批准', '已拒絕'].includes(status)) {
      return res.status(400).json({ error: '無效的審核狀態' });
    }

    // 1. 更新請假單狀態
    const { data: request, error: updateError } = await supabase
      .from('leave_requests')
      .update({ status: status })
      .eq('id', id)
      .select()
      .single();

    if (updateError) throw updateError;

    // 2. 如果是「已批准」，自動把該學生的點名紀錄設為「請假」(且不扣課時 deduct_credits: 0)
    if (status === '已批准') {
      await supabase
        .from('attendance')
        .upsert({
          schedule_id: request.schedule_id,
          student_id: request.student_id,
          status: '請假',
          deduct_credits: 0 // 請假通常不扣課時，可依你們的規定調整
        }, { onConflict: 'schedule_id, student_id' });
    }

    res.json({ message: `已成功將請假單設為：${status}` });

  } catch (error) {
    console.error('審核請假錯誤:', error);
    res.status(500).json({ error: '審核失敗' });
  }
});
// 4. 取得家長的小孩名單與近期課程 (請假下拉選單用)
app.get('/api/parent/leave-options', authenticateToken, async (req, res) => {
  try {
    const { userId, role } = req.user;
    if (role !== 'parent') return res.status(403).json({ error: '僅限家長' });

    // A. 找出該家長綁定的孩子
    const { data: relations } = await supabase.from('parent_child').select('child_id').eq('parent_id', userId);
    if (!relations || relations.length === 0) return res.json({ children: [], schedules: [] });
    
    const childIds = relations.map(r => r.child_id);
    const { data: children } = await supabase.from('users').select('id, username').in('id', childIds);

    // B. 找出這些孩子報名的班級
    const { data: enrolled } = await supabase.from('student_classes').select('student_id, class_id').in('student_id', childIds);
    if (!enrolled || enrolled.length === 0) return res.json({ children, schedules: [] });
    
    const classIds = enrolled.map(e => e.class_id);

    // C. 找出這些班級「未來」的排課
    const today = new Date().toISOString().split('T')[0];
    const { data: schedules } = await supabase
      .from('class_schedules')
      .select('id, class_id, class_date, start_time, classes(name)')
      .in('class_id', classIds)
      .gte('class_date', today)
      .order('class_date', { ascending: true });

    // D. 把資料整理好傳給前端
    const availableSchedules = schedules.map(s => {
      // 找出這堂課是屬於哪個小孩的
      const studentIdsForThisClass = enrolled.filter(e => e.class_id === s.class_id).map(e => e.student_id);
      return {
        id: s.id,
        student_ids: studentIdsForThisClass,
        label: `${s.class_date} ${s.start_time.substring(0,5)} - ${s.classes.name}`
      };
    });

    res.json({ children, schedules: availableSchedules });
  } catch (error) {
    console.error('獲取請假選項失敗:', error);
    res.status(500).json({ error: '獲取請假選項失敗' });
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
